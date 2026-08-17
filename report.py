# generating the report on abnormalities detected in the collected windows event logs

from __future__ import annotations

import argparse
import html
import json
import logging
import sqlite3
import sys
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # rule metadata becomes optional rather than fatal

LOG = logging.getLogger("report")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# Palette: cool forensic-lab neutrals with a single warm severity ramp.
SEV_COLOUR = {
    "critical": "#9E2A2B",
    "high": "#C2571A",
    "medium": "#B08400",
    "low": "#5A7D8C",
    "informational": "#8A94A0",
}


# -----------------------------------------Data loading----------------------------------


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def query(db: Path, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    if not db.is_file():
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params)]
    except sqlite3.Error as exc:
        LOG.warning("Query failed on %s: %s", db.name, exc)
        return []
    finally:
        conn.close()


def load_rule_metadata(rules_dir: Path) -> dict[str, dict[str, Any]]:
    """Rule descriptions and false-positive notes, keyed by rule id."""
    meta: dict[str, dict[str, Any]] = {}
    if yaml is None or not rules_dir.is_dir():
        return meta
    for path in sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))):
        try:
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if doc and "id" in doc:
                    meta[str(doc["id"])] = doc
        except yaml.YAMLError:
            continue
    return meta


# -----------------------------------------SVG charts----------------------------------


def svg_severity(counts: dict[str, int]) -> str:
    """Horizontal bars. Ordered by severity, not by count - rank is the point."""
    rows = [(s, counts.get(s, 0)) for s in SEVERITY_ORDER if counts.get(s, 0)]
    if not rows:
        return '<p class="empty">No alerts raised.</p>'

    peak = max(n for _, n in rows)
    bar_h, gap, label_w, track_w = 26, 10, 104, 420
    height = len(rows) * (bar_h + gap)
    parts = [
        f'<svg viewBox="0 0 {label_w + track_w + 54} {height}" '
        f'role="img" aria-label="Alerts by severity" class="chart">'
    ]
    for i, (sev, count) in enumerate(rows):
        y = i * (bar_h + gap)
        width = max(3, int(track_w * count / peak))
        parts.append(
            f'<text x="0" y="{y + bar_h - 8}" class="svg-label">{sev.upper()}</text>'
            f'<rect x="{label_w}" y="{y}" width="{track_w}" height="{bar_h}" '
            f'fill="#EDF0F3"/>'
            f'<rect x="{label_w}" y="{y}" width="{width}" height="{bar_h}" '
            f'fill="{SEV_COLOUR[sev]}"/>'
            f'<text x="{label_w + width + 10}" y="{y + bar_h - 8}" '
            f'class="svg-value">{count}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def svg_timeline(alerts: list[dict[str, Any]]) -> str:
    """Alert volume per hour, stacked by severity."""
    buckets: dict[str, Counter] = defaultdict(Counter)
    for alert in alerts:
        ts = str(alert.get("timestamp") or "")
        if len(ts) >= 13:
            buckets[ts[:13]][alert.get("severity", "informational")] += 1
    if not buckets:
        return '<p class="empty">No timestamped alerts to plot.</p>'

    hours = sorted(buckets)
    peak = max(sum(c.values()) for c in buckets.values())
    width, height = 760, 150
    slot = width / max(len(hours), 1)
    bar_w = max(6, min(38, slot * 0.62))

    parts = [
        f'<svg viewBox="0 0 {width} {height + 34}" role="img" '
        f'aria-label="Alert timeline" class="chart">',
        f'<line x1="0" y1="{height}" x2="{width}" y2="{height}" stroke="#D8DEE4"/>',
    ]
    for i, hour in enumerate(hours):
        x = i * slot + (slot - bar_w) / 2
        y = height
        for sev in SEVERITY_ORDER:
            n = buckets[hour][sev]
            if not n:
                continue
            seg = (n / peak) * (height - 12)
            y -= seg
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
                f'height="{seg:.1f}" fill="{SEV_COLOUR[sev]}"/>'
            )
        label = hour[11:13] + ":00"
        if len(hours) <= 26 or i % 2 == 0:
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{height + 16}" '
                f'class="svg-tick" text-anchor="middle">{label}</text>'
            )
    day = hours[0][:10]
    parts.append(
        f'<text x="0" y="{height + 31}" class="svg-tick">{day} (UTC)</text></svg>'
    )
    return "".join(parts)


# --------------------------------------ATT&CK Navigator layer-------------------------------------


def build_navigator_layer(alerts: list[dict[str, Any]], title: str) -> dict[str, Any]:
    scores: Counter = Counter()
    rules_per_tech: dict[str, set] = defaultdict(set)
    for alert in alerts:
        for tech in str(alert.get("techniques") or "").split(","):
            tech = tech.strip()
            if tech:
                scores[tech] += 1
                rules_per_tech[tech].add(alert.get("rule_id"))

    return {
        "name": f"{title} - detection coverage",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques evidenced by alerts raised during this collection. "
            "Score is the number of alerts, not a confidence measure."
        ),
        "techniques": [
            {
                "techniqueID": tech,
                "score": count,
                "color": "",
                "comment": "Rules: " + ", ".join(sorted(
                    r for r in rules_per_tech[tech] if r)),
                "enabled": True,
            }
            for tech, count in sorted(scores.items())
        ],
        "gradient": {
            "colors": ["#EDF0F3", "#C2571A", "#9E2A2B"],
            "minValue": 0,
            "maxValue": max(scores.values()) if scores else 1,
        },
        "legendItems": [
            {"label": "Alert raised for this technique", "color": "#C2571A"}
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#16202B",
        "sorting": 3,
    }


# -------------------------------------HTML--------------------------------------

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --ink:#16202B; --paper:#FBFBF9; --muted:#5F6B78; --rule:#D8DEE4;
  --steel:#4A6480; --panel:#F3F5F7;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
  --sans:"Segoe UI",-apple-system,Roboto,Helvetica,Arial,sans-serif;
}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.sheet{max-width:1080px;margin:0 auto;padding:44px 40px 88px}
a{color:var(--steel)}

/* Masthead */
.masthead{border-bottom:2px solid var(--ink);padding-bottom:18px;margin-bottom:0}
.kicker{font-family:var(--mono);font-size:11px;letter-spacing:.18em;
  text-transform:uppercase;color:var(--muted)}
h1{font-size:29px;line-height:1.15;margin:.32em 0 .1em;font-weight:600;
  letter-spacing:-.015em}
.subject{font-family:var(--mono);font-size:13px;color:var(--steel)}

/* Evidence seal - the signature element */
.seal{display:flex;flex-wrap:wrap;gap:0;border:1px solid var(--rule);
  border-left:5px solid var(--steel);background:#fff;margin:24px 0 34px}
.seal.failed{border-left-color:var(--sev-critical,#9E2A2B)}
.seal-stamp{padding:16px 22px;border-right:1px solid var(--rule);
  display:flex;flex-direction:column;justify-content:center;min-width:168px}
.stamp-mark{font-family:var(--mono);font-size:13px;font-weight:700;
  letter-spacing:.12em;border:2px solid currentColor;padding:5px 10px;
  display:inline-block;transform:rotate(-2.5deg);text-align:center}
.stamp-ok{color:#2F6B4F}
.stamp-bad{color:#9E2A2B}
.seal-body{padding:14px 22px;flex:1;min-width:260px}
.seal-body dl{display:grid;grid-template-columns:auto 1fr;gap:2px 18px;margin:0;
  font-family:var(--mono);font-size:12px}
.seal-body dt{color:var(--muted)}
.seal-body dd{margin:0;word-break:break-all}

/* Sections */
section{margin:40px 0 0}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--muted);font-weight:600;
  border-bottom:1px solid var(--rule);padding-bottom:7px;margin:0 0 18px}
h2 .idx{color:var(--steel);margin-right:10px}
h3{font-size:16px;margin:26px 0 10px;font-weight:600}

/* Metrics */
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));
  gap:1px;background:var(--rule);border:1px solid var(--rule)}
.metric{background:#fff;padding:14px 16px}
.metric .n{font-family:var(--mono);font-size:25px;font-weight:600;
  letter-spacing:-.02em;display:block;line-height:1.1}
.metric .k{font-size:11px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em}

/* Charts */
.chart{width:100%;height:auto;margin:6px 0 4px}
.svg-label{font-family:var(--mono);font-size:11px;fill:var(--muted);
  letter-spacing:.08em}
.svg-value{font-family:var(--mono);font-size:12px;fill:var(--ink);font-weight:600}
.svg-tick{font-family:var(--mono);font-size:9.5px;fill:var(--muted)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:34px}
@media(max-width:820px){.two-col{grid-template-columns:1fr}}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--muted);font-weight:600;
  border-bottom:1px solid var(--rule);padding:7px 10px 7px 0}
td{padding:7px 10px 7px 0;border-bottom:1px solid #EDF0F3;vertical-align:top}
td.mono,.mono{font-family:var(--mono);font-size:12px}
tbody tr:hover{background:#F7F9FA}

/* Exhibits */
.exhibit{border:1px solid var(--rule);border-left:4px solid var(--sev);
  background:#fff;margin:0 0 12px;padding:0}
.exhibit summary{padding:13px 18px;cursor:pointer;display:flex;gap:14px;
  align-items:baseline;list-style:none}
.exhibit summary::-webkit-details-marker{display:none}
.exhibit summary:hover{background:#F7F9FA}
.exhibit summary:focus-visible{outline:2px solid var(--steel);outline-offset:-2px}
.ex-no{font-family:var(--mono);font-size:11px;color:var(--muted);
  letter-spacing:.06em;flex-shrink:0}
.ex-title{font-weight:600;flex:1}
.ex-sev{font-family:var(--mono);font-size:10px;letter-spacing:.1em;
  text-transform:uppercase;color:#fff;background:var(--sev);
  padding:2px 8px;border-radius:2px;flex-shrink:0}
.ex-time{font-family:var(--mono);font-size:11.5px;color:var(--muted);flex-shrink:0}
.ex-body{padding:4px 18px 18px;border-top:1px solid var(--rule);background:#FCFDFD}
.ex-body p{margin:12px 0 10px;color:#333B45;max-width:70ch}
.ex-body dl{display:grid;grid-template-columns:auto 1fr;gap:3px 16px;margin:10px 0;
  font-family:var(--mono);font-size:12px}
.ex-body dt{color:var(--muted);white-space:nowrap}
.ex-body dd{margin:0;word-break:break-all}
.fp{border-left:2px solid var(--rule);padding:2px 0 2px 12px;margin:12px 0 0;
  font-size:12.5px;color:var(--muted)}
.fp strong{color:var(--ink);font-weight:600}
.tech{font-family:var(--mono);font-size:11px;background:var(--panel);
  padding:1px 6px;border:1px solid var(--rule);margin-right:4px;
  display:inline-block}

.empty{color:var(--muted);font-style:italic;font-size:13.5px}
.note{background:var(--panel);border-left:3px solid var(--steel);
  padding:12px 16px;font-size:13px;color:#333B45;margin:14px 0}
footer{margin-top:56px;padding-top:16px;border-top:1px solid var(--rule);
  font-family:var(--mono);font-size:11px;color:var(--muted)}

@media print{
  body{font-size:11pt}
  .sheet{max-width:none;padding:0}
  .exhibit{break-inside:avoid;page-break-inside:avoid}
  .exhibit[open] .ex-body{display:block}
  details{open:true}
  section{break-inside:auto}
  h2{break-after:avoid}
  tbody tr:hover{background:none}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""


def esc(value: Any) -> str:
    return html.escape(str(value)) if value not in (None, "") else ""


def dl(pairs: list[tuple[str, Any]]) -> str:
    rows = [f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in pairs if v not in (None, "")]
    return f"<dl>{''.join(rows)}</dl>" if rows else ""


EVIDENCE_FIELDS = [
    ("Host", "computer"), ("Channel", "channel"), ("Event ID", "event_id"),
    ("Record", "record_id"), ("User", "user_name"), ("Target user", "target_user_name"),
    ("Process", "process_path"), ("Command line", "process_command_line"),
    ("Parent", "parent_process_name"), ("Source IP", "src_ip"),
    ("Destination IP", "dst_ip"), ("File", "file_path"),
    ("Registry key", "registry_key"), ("Service", "service_name"),
    ("Task", "task_name"), ("Correlated on", "correlation_key"),
    ("Events in window", "match_count"), ("Sample records", "sample_record_ids"),
]


def render_exhibit(index: int, alert: dict[str, Any],
                   meta: dict[str, Any]) -> str:
    sev = alert.get("severity", "informational")
    colour = SEV_COLOUR.get(sev, SEV_COLOUR["informational"])
    techs = [t.strip() for t in str(alert.get("techniques") or "").split(",") if t.strip()]

    description = str(meta.get("description", "")).strip()
    fps = meta.get("false_positives") or []
    refs = meta.get("references") or []

    evidence = dl([(label, alert.get(key)) for label, key in EVIDENCE_FIELDS])
    tech_html = "".join(f'<span class="tech">{esc(t)}</span>' for t in techs)
    fp_html = ""
    if fps:
        items = "; ".join(esc(f) for f in fps)
        fp_html = (f'<p class="fp"><strong>Known benign causes:</strong> {items}</p>')
    ref_html = ""
    if refs:
        links = " ".join(
            f'<a href="{esc(r)}" rel="noreferrer">{esc(r)}</a>' for r in refs)
        ref_html = f'<p class="fp"><strong>Reference:</strong> {links}</p>'

    return f"""
<details class="exhibit" style="--sev:{colour}">
  <summary>
    <span class="ex-no">EX-{index:03d}</span>
    <span class="ex-title">{esc(alert.get('rule_title'))}</span>
    <span class="ex-time">{esc(alert.get('timestamp'))}</span>
    <span class="ex-sev">{esc(sev)}</span>
  </summary>
  <div class="ex-body">
    {f'<p>{esc(description)}</p>' if description else ''}
    <p class="mono">Rule: {esc(alert.get('rule_id'))} &nbsp; {tech_html}</p>
    {evidence}
    {fp_html}
    {ref_html}
  </div>
</details>"""


def render_html(ctx: dict[str, Any]) -> str:
    alerts = ctx["alerts"]
    sev_counts = Counter(a.get("severity", "informational") for a in alerts)
    integrity = ctx["integrity"]
    verified = integrity.get("verified")

    stamp = ('<span class="stamp-mark stamp-ok">SEAL INTACT</span>' if verified
             else '<span class="stamp-mark stamp-bad">SEAL BROKEN</span>')
    seal_note = (f"{integrity.get('files_matched', 0)} files verified"
                 if verified else
                 f"{len(integrity.get('files_mismatched') or [])} mismatched, "
                 f"{len(integrity.get('files_missing') or [])} missing")

    exhibits = "".join(
        render_exhibit(i, a, ctx["rule_meta"].get(a.get("rule_id"), {}))
        for i, a in enumerate(alerts, start=1)
    ) or '<p class="empty">No alerts were raised against this collection.</p>'

    # Technique table
    tech_rows = []
    tech_counter: Counter = Counter()
    for alert in alerts:
        for t in str(alert.get("techniques") or "").split(","):
            if t.strip():
                tech_counter[t.strip()] += 1
    for tech, count in tech_counter.most_common():
        rules = sorted({a["rule_id"] for a in alerts
                        if tech in str(a.get("techniques") or "")})
        tech_rows.append(
            f"<tr><td class='mono'>{esc(tech)}</td><td>{count}</td>"
            f"<td class='mono'>{esc(', '.join(rules))}</td></tr>")
    tech_table = (
        "<table><thead><tr><th>Technique</th><th>Alerts</th><th>Rules</th>"
        "</tr></thead><tbody>" + "".join(tech_rows) + "</tbody></table>"
        if tech_rows else '<p class="empty">No techniques evidenced.</p>')

    # Channel coverage
    chan_rows = "".join(
        f"<tr><td class='mono'>{esc(c['channel_key'])}</td>"
        f"<td>{c['n']}</td><td>{c['mapped']}</td>"
        f"<td>{(100 * c['mapped'] // c['n']) if c['n'] else 0}%</td></tr>"
        for c in ctx["channels"]
    )
    chan_table = (
        "<table><thead><tr><th>Channel</th><th>Events</th><th>Normalised</th>"
        "<th>Coverage</th></tr></thead><tbody>" + chan_rows + "</tbody></table>"
        if chan_rows else '<p class="empty">No events parsed.</p>')

    # Silent rules
    fired = {a["rule_id"] for a in alerts}
    silent = sorted(r for r in ctx["rule_meta"] if r not in fired)
    silent_rows = "".join(
        f"<tr><td class='mono'>{esc(r)}</td>"
        f"<td>{esc(ctx['rule_meta'][r].get('severity', ''))}</td>"
        f"<td>{esc(ctx['rule_meta'][r].get('title', ''))}</td></tr>"
        for r in silent
    )
    silent_table = (
        "<table><thead><tr><th>Rule</th><th>Severity</th><th>Title</th></tr>"
        "</thead><tbody>" + silent_rows + "</tbody></table>"
        if silent_rows else '<p class="empty">Every rule produced at least one alert.</p>')

    unmapped = ctx["unmapped"]
    unmapped_rows = "".join(
        f"<tr><td class='mono'>{esc(k)}</td><td>{v}</td></tr>"
        for k, v in list(unmapped.items())[:15])
    unmapped_table = (
        "<table><thead><tr><th>Channel / Event ID</th><th>Count</th></tr></thead>"
        "<tbody>" + unmapped_rows + "</tbody></table>"
        if unmapped_rows else '<p class="empty">All events matched a field mapper.</p>')

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(ctx['title'])} - Event Log Analysis Report</title>
<style>{CSS}</style>
</head><body>
<div class="sheet">

<header class="masthead">
  <div class="kicker">Windows Event Log Analysis &middot; Automated Report</div>
  <h1>{esc(ctx['title'])}</h1>
  <div class="subject">{esc(ctx['hostname'])} &middot; collection window
    {esc(ctx['window_start'])} to {esc(ctx['window_end'])}</div>
</header>

<div class="seal {'' if verified else 'failed'}">
  <div class="seal-stamp">{stamp}
    <div class="mono" style="font-size:10.5px;color:#5F6B78;margin-top:7px">
      {esc(seal_note)}</div>
  </div>
  <div class="seal-body">
    {dl([
        ("Collection", ctx["collection_id"]),
        ("Acquired", ctx["collected_at"]),
        ("Operator", ctx["collected_by"]),
        ("Elevated", ctx["elevated"]),
        ("Evidence path", ctx["collection_dir"]),
    ])}
  </div>
</div>

<section>
  <h2><span class="idx">01</span>Summary</h2>
  <div class="metrics">
    <div class="metric"><span class="n">{ctx['total_events']}</span>
      <span class="k">Events</span></div>
    <div class="metric"><span class="n">{ctx['normalised']}</span>
      <span class="k">Normalised</span></div>
    <div class="metric"><span class="n">{ctx['rules_run']}</span>
      <span class="k">Rules run</span></div>
    <div class="metric"><span class="n">{len(alerts)}</span>
      <span class="k">Alerts</span></div>
    <div class="metric"><span class="n">{sev_counts.get('critical', 0)}</span>
      <span class="k">Critical</span></div>
    <div class="metric"><span class="n">{len(tech_counter)}</span>
      <span class="k">Techniques</span></div>
  </div>
  {'<p class="note">' + esc(ctx['headline']) + '</p>' if ctx['headline'] else ''}
</section>

<section>
  <h2><span class="idx">02</span>Alert profile</h2>
  <div class="two-col">
    <div><h3>By severity</h3>{svg_severity(sev_counts)}</div>
    <div><h3>Over time</h3>{svg_timeline(alerts)}</div>
  </div>
</section>

<section>
  <h2><span class="idx">03</span>ATT&amp;CK techniques evidenced</h2>
  {tech_table}
  <p class="note">Technique attribution is made by the rule that fired, not by
  the event identifier alone. A Navigator layer is written alongside this
  report as <span class="mono">attack_layer.json</span>.</p>
</section>

<section>
  <h2><span class="idx">04</span>Exhibits</h2>
  {exhibits}
</section>

<section>
  <h2><span class="idx">05</span>Telemetry coverage</h2>
  {chan_table}
  <h3>Event IDs without a field mapper</h3>
  {unmapped_table}
</section>

<section>
  <h2><span class="idx">06</span>Rules that did not fire</h2>
  <p class="note">Listed for honesty about coverage. A rule producing no alerts
  may mean the activity was absent, or that the telemetry needed to detect it
  was never collected - these are different conclusions and only the channel
  table above distinguishes them.</p>
  {silent_table}
</section>

<footer>
  Generated {esc(ctx['generated'])} &middot; pipeline v1.0.0 &middot;
  events {esc(ctx['events_db'])}
</footer>
</div></body></html>"""


# Markdown report

def render_markdown(ctx: dict[str, Any]) -> str:
    alerts = ctx["alerts"]
    sev = Counter(a.get("severity", "informational") for a in alerts)
    lines = [
        f"# {ctx['title']} - Event Log Analysis Report", "",
        f"- **Host:** {ctx['hostname']}",
        f"- **Collection:** {ctx['collection_id']}",
        f"- **Window:** {ctx['window_start']} to {ctx['window_end']}",
        f"- **Evidence integrity:** "
        f"{'verified' if ctx['integrity'].get('verified') else 'NOT VERIFIED'}",
        f"- **Generated:** {ctx['generated']}", "",
        "## Summary", "",
        "| Metric | Value |", "|---|---|",
        f"| Events collected | {ctx['total_events']} |",
        f"| Events normalised | {ctx['normalised']} |",
        f"| Rules evaluated | {ctx['rules_run']} |",
        f"| Alerts raised | {len(alerts)} |",
    ]
    for s in SEVERITY_ORDER:
        if sev.get(s):
            lines.append(f"| {s.capitalize()} alerts | {sev[s]} |")
    lines += ["", "## Alerts", ""]
    if alerts:
        lines += ["| # | Severity | Rule | Technique | Time |", "|---|---|---|---|---|"]
        for i, a in enumerate(alerts, 1):
            lines.append(
                f"| EX-{i:03d} | {a.get('severity')} | {a.get('rule_title')} "
                f"| {a.get('techniques') or '-'} | {a.get('timestamp')} |")
    else:
        lines.append("_No alerts raised._")
    return "\n".join(lines) + "\n"


# --------------------------------------Assembly-------------------------------------


def locate(target: Path) -> Path:
    """Find the parsed folder from a parsed dir, collection dir, or ancestor."""
    target = target.expanduser().resolve()
    for candidate in (target, target / "parsed"):
        if (candidate / "events.sqlite").is_file():
            return candidate
    found = sorted((p.parent for p in target.rglob("events.sqlite")),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if found:
        LOG.warning("Auto-selected newest parsed folder: %s", found[0])
        return found[0]
    raise FileNotFoundError(
        f"No events.sqlite found at or under {target}. Run parse_eventlogs.py first.")


def build_context(parsed: Path, rules_dir: Path, title: str | None) -> dict[str, Any]:
    parse_report = read_json(parsed / "parse_report.json")
    detect_report = read_json(parsed / "detection_report.json")
    integrity = parse_report.get("integrity") or {}
    stats = parse_report.get("statistics") or {}

    collection_dir = Path(parse_report.get("collection_dir", parsed.parent))
    manifest = read_json(collection_dir / "manifest.json")

    alerts = query(parsed / "alerts.sqlite",
                   "SELECT * FROM alerts ORDER BY "
                   "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                   "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, timestamp")

    channels = query(parsed / "events.sqlite",
                     "SELECT channel_key, COUNT(*) n, SUM(mapped) mapped "
                     "FROM events GROUP BY channel_key ORDER BY n DESC")

    sev = Counter(a.get("severity") for a in alerts)
    crit_high = sev.get("critical", 0) + sev.get("high", 0)
    if not alerts:
        headline = ("No rule matched this collection. Check the telemetry "
                    "coverage table below before concluding the host is clean.")
    elif crit_high:
        headline = (f"{crit_high} alert(s) at high or critical severity require "
                    f"triage. Exhibits are ordered by severity.")
    else:
        headline = "All alerts are medium severity or below."

    return {
        "title": title or manifest.get("CollectionId") or parsed.parent.name,
        "hostname": manifest.get("Hostname") or integrity.get("hostname") or "unknown",
        "collection_id": manifest.get("CollectionId") or integrity.get("collection_id"),
        "collected_at": manifest.get("CollectedAtUtc"),
        "collected_by": manifest.get("CollectedBy"),
        "elevated": manifest.get("Elevated"),
        "collection_dir": str(collection_dir),
        "events_db": str(parsed / "events.sqlite"),
        "window_start": (manifest.get("WindowStartUtc")
                         or integrity.get("window_start_utc") or "?"),
        "window_end": (manifest.get("WindowEndUtc")
                       or integrity.get("window_end_utc") or "?"),
        "integrity": integrity,
        "total_events": stats.get("total_events", 0),
        "normalised": stats.get("normalised", 0),
        "unmapped": stats.get("unmapped_event_ids") or {},
        "rules_run": detect_report.get("rules_evaluated", 0),
        "alerts": alerts,
        "channels": channels,
        "rule_meta": load_rule_metadata(rules_dir),
        "headline": headline,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
    }


def main(argv: list[str] | None = None) -> int:
    script_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(
        description="Generate a forensic report from a parsed collection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("target", type=Path, nargs="?", default=Path.cwd(),
                    help="Parsed folder, collection folder, or a parent of one")
    ap.add_argument("--rules", type=Path, default=script_dir / "rules")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output folder (default: alongside events.sqlite)")
    ap.add_argument("--title", default=None, help="Report title")
    ap.add_argument("--open", action="store_true",
                    help="Open the report in the default browser")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    if yaml is None:
        LOG.warning("PyYAML not installed - rule descriptions will be omitted.")

    try:
        parsed = locate(args.target)
    except FileNotFoundError as exc:
        LOG.error("%s", exc)
        return 2

    ctx = build_context(parsed, args.rules.expanduser().resolve(), args.title)
    out_dir = (args.out or parsed).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    html_path = out_dir / "report.html"
    html_path.write_text(render_html(ctx), encoding="utf-8")

    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(ctx), encoding="utf-8")

    layer_path = out_dir / "attack_layer.json"
    layer_path.write_text(
        json.dumps(build_navigator_layer(ctx["alerts"], ctx["title"]), indent=2),
        encoding="utf-8")

    LOG.info("-" * 58)
    LOG.info("Alerts    : %d", len(ctx["alerts"]))
    LOG.info("Report    : %s", html_path)
    LOG.info("Markdown  : %s", md_path)
    LOG.info("ATT&CK    : %s", layer_path)
    LOG.info("-" * 58)

    if args.open:
        webbrowser.open(html_path.as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())

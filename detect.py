# detecting the abnormalities in the parsed windows event logs

from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "PyYAML is required for the detection engine.\n"
        "Install it with:  pip install pyyaml\n"
    )
    raise SystemExit(3)

LOG = logging.getLogger("detect")

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Columns the engine will allow rules to reference. Anything else is a typo,
# and a silently-never-firing rule is worse than a loud error.
from parse_eventlogs import COLUMNS  # noqa: E402

VALID_FIELDS = set(COLUMNS)


# ------------------------------------Rule model---------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    author: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    detection: dict[str, Any] = field(default_factory=dict)
    correlation: dict[str, Any] | None = None
    enabled: bool = True
    source_file: str = ""

    @property
    def is_correlation(self) -> bool:
        return bool(self.correlation)


class RuleError(Exception):
    """Raised for malformed rules - always names the rule and the problem."""


# -----------------------------------------Field expression compiler----------------------------------

LIKE_ESCAPE = "\\"


def _escape_like(value: str) -> str:
    """Neutralise LIKE wildcards in user-supplied literals."""
    out = value.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
    return out.replace("%", LIKE_ESCAPE + "%").replace("_", LIKE_ESCAPE + "_")


def compile_field(spec: str, value: Any, rule_id: str) -> tuple[str, list[Any]]:
    """
    Compile one `field|modifier: value` pair into SQL.

    A list value is an implicit OR unless the `all` modifier is present.
    Matching is case-insensitive throughout - Windows paths and account names
    vary in case between channels and between events on the same host.
    """
    parts = spec.split("|")
    fieldname = parts[0].strip()
    modifiers = [m.strip().lower() for m in parts[1:]]

    if fieldname not in VALID_FIELDS:
        raise RuleError(
            f"[{rule_id}] unknown field '{fieldname}'. "
            f"It is not a column in the normalised schema."
        )

    negate = "not" in modifiers
    require_all = "all" in modifiers
    modifiers = [m for m in modifiers if m not in ("not", "all")]
    op = modifiers[0] if modifiers else "equals"

    col = f'"{fieldname}"'
    values = value if isinstance(value, list) else [value]

    clauses: list[str] = []
    params: list[Any] = []

    for item in values:
        if item is None:
            clauses.append(f"{col} IS NULL")
            continue

        text = str(item)
        if op == "equals":
            clauses.append(f"{col} = ? COLLATE NOCASE")
            params.append(text)
        elif op == "contains":
            clauses.append(f"{col} LIKE ? ESCAPE '{LIKE_ESCAPE}'")
            params.append(f"%{_escape_like(text)}%")
        elif op == "startswith":
            clauses.append(f"{col} LIKE ? ESCAPE '{LIKE_ESCAPE}'")
            params.append(f"{_escape_like(text)}%")
        elif op == "endswith":
            clauses.append(f"{col} LIKE ? ESCAPE '{LIKE_ESCAPE}'")
            params.append(f"%{_escape_like(text)}")
        elif op in ("re", "regex"):
            clauses.append(f"{col} REGEXP ?")
            params.append(text)
        elif op in ("gt", "gte", "lt", "lte"):
            sql_op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            clauses.append(f"CAST({col} AS INTEGER) {sql_op} ?")
            params.append(int(item))
        elif op == "exists":
            clauses.append(
                f"({col} IS NOT NULL AND {col} != '')" if str(item).lower() == "true"
                else f"({col} IS NULL OR {col} = '')"
            )
        else:
            raise RuleError(f"[{rule_id}] unsupported modifier '{op}' on '{fieldname}'")

    joiner = " AND " if require_all else " OR "
    sql = "(" + joiner.join(clauses) + ")"
    if negate:
        # IS NOT NULL guard: in SQL, NULL <> 'x' is NULL, not true, so a plain
        # NOT would silently drop every event where the field is absent.
        sql = f"(NOT {sql} OR {col} IS NULL)"
    return sql, params


def compile_selection(sel: Any, rule_id: str) -> tuple[str, list[Any]]:
    """A selection is a map (AND of fields) or a list of maps (OR of those)."""
    if isinstance(sel, list):
        subs = [compile_selection(item, rule_id) for item in sel]
        sql = "(" + " OR ".join(s for s, _ in subs) + ")"
        params: list[Any] = []
        for _, p in subs:
            params.extend(p)
        return sql, params

    if not isinstance(sel, dict):
        raise RuleError(f"[{rule_id}] selection must be a map or list of maps")

    clauses, params = [], []
    for key, val in sel.items():
        sql, prm = compile_field(key, val, rule_id)
        clauses.append(sql)
        params.extend(prm)
    return "(" + " AND ".join(clauses) + ")", params


# -------------------------------------Condition parser--------------------------------------

TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not|of|all|any|1)\b|[A-Za-z_][A-Za-z0-9_]*\*?")


class ConditionParser:
    """
    Recursive-descent parser for the Sigma-style condition grammar subset:

        expr       := term ('or' term)*
        term       := factor ('and' factor)*
        factor     := 'not' factor | '(' expr ')' | quantifier | identifier
        quantifier := ('1'|'any'|'all') 'of' identifier['*']

    Emits SQL with parameters collected in emission order.
    """

    def __init__(self, condition: str, selections: dict[str, tuple[str, list]],
                 rule_id: str) -> None:
        self.tokens = TOKEN_RE.findall(condition.lower().strip())
        self.pos = 0
        self.selections = selections
        self.rule_id = rule_id
        self.params: list[Any] = []

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str | None:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse(self) -> tuple[str, list[Any]]:
        sql = self.expr()
        if self.peek() is not None:
            raise RuleError(
                f"[{self.rule_id}] trailing tokens in condition near "
                f"'{self.peek()}'"
            )
        return sql, self.params

    def expr(self) -> str:
        left = self.term()
        while self.peek() == "or":
            self.next()
            left = f"({left} OR {self.term()})"
        return left

    def term(self) -> str:
        left = self.factor()
        while self.peek() == "and":
            self.next()
            left = f"({left} AND {self.factor()})"
        return left

    def factor(self) -> str:
        tok = self.next()
        if tok is None:
            raise RuleError(f"[{self.rule_id}] condition ended unexpectedly")
        if tok == "not":
            return f"(NOT {self.factor()})"
        if tok == "(":
            inner = self.expr()
            if self.next() != ")":
                raise RuleError(f"[{self.rule_id}] unbalanced parentheses")
            return f"({inner})"
        if tok in ("1", "any", "all"):
            if self.next() != "of":
                raise RuleError(f"[{self.rule_id}] expected 'of' after '{tok}'")
            pattern = self.next() or ""
            return self.quantifier(tok, pattern)
        return self.identifier(tok)

    def quantifier(self, kind: str, pattern: str) -> str:
        if pattern in ("them", "them*"):
            names = list(self.selections)
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            names = [n for n in self.selections if n.startswith(prefix)]
        else:
            names = [pattern] if pattern in self.selections else []

        if not names:
            raise RuleError(
                f"[{self.rule_id}] '{kind} of {pattern}' matched no selections"
            )
        joiner = " AND " if kind == "all" else " OR "
        fragments = []
        for name in names:
            sql, prm = self.selections[name]
            fragments.append(sql)
            self.params.extend(prm)
        return "(" + joiner.join(fragments) + ")"

    def identifier(self, name: str) -> str:
        if name not in self.selections:
            raise RuleError(
                f"[{self.rule_id}] condition references undefined selection "
                f"'{name}'. Defined: {', '.join(self.selections) or '(none)'}"
            )
        sql, prm = self.selections[name]
        self.params.extend(prm)
        return sql


def compile_rule(rule: Rule) -> tuple[str, list[Any]]:
    """Compile a rule's detection block into a SQL WHERE clause."""
    detection = dict(rule.detection)
    condition = detection.pop("condition", None)
    if not detection:
        raise RuleError(f"[{rule.id}] detection block has no selections")

    selections = {
        name.lower(): compile_selection(sel, rule.id)
        for name, sel in detection.items()
    }

    if not condition:
        # No explicit condition: AND everything, which is the common case.
        parts, params = [], []
        for sql, prm in selections.values():
            parts.append(sql)
            params.extend(prm)
        return " AND ".join(parts), params

    return ConditionParser(str(condition), selections, rule.id).parse()


# -------------------------------------Rule loading--------------------------------------

REQUIRED_KEYS = ("id", "title", "detection")


def load_rules(rules_dir: Path) -> list[Rule]:
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"Rules folder not found: {rules_dir}")

    rules: list[Rule] = []
    seen: dict[str, str] = {}

    files = sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml")))
    if not files:
        raise FileNotFoundError(f"No .yml/.yaml rule files in {rules_dir}")

    for path in files:
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            LOG.error("Skipping %s - invalid YAML: %s", path.name, exc)
            continue

        for doc in documents:
            if not doc:
                continue
            missing = [k for k in REQUIRED_KEYS if k not in doc]
            if missing:
                LOG.error("Skipping a rule in %s - missing %s",
                          path.name, ", ".join(missing))
                continue

            rule = Rule(
                id=str(doc["id"]),
                title=str(doc["title"]),
                description=str(doc.get("description", "")).strip(),
                severity=str(doc.get("severity", "medium")).lower(),
                author=str(doc.get("author", "")),
                references=list(doc.get("references") or []),
                tags=list(doc.get("tags") or []),
                techniques=[str(t) for t in (doc.get("techniques") or [])],
                false_positives=list(doc.get("false_positives") or []),
                detection=doc.get("detection") or {},
                correlation=doc.get("correlation"),
                enabled=bool(doc.get("enabled", True)),
                source_file=path.name,
            )

            if rule.severity not in SEVERITY_ORDER:
                LOG.warning("[%s] unknown severity '%s', treating as medium",
                            rule.id, rule.severity)
                rule.severity = "medium"

            if rule.id in seen:
                LOG.error("Duplicate rule id '%s' in %s (first seen in %s) - skipped",
                          rule.id, path.name, seen[rule.id])
                continue
            seen[rule.id] = path.name
            rules.append(rule)

    return rules


# ------------------------------------Time helpers---------------------------------------

TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhd])$", re.IGNORECASE)
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timespan(text: str) -> timedelta:
    match = TIMESPAN_RE.match(str(text).strip())
    if not match:
        raise RuleError(f"Invalid timespan '{text}' (expected e.g. 30s, 5m, 1h, 1d)")
    return timedelta(seconds=int(match.group(1)) * UNIT_SECONDS[match.group(2).lower()])


def parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


# ----------------------------------------Engine-----------------------------------

ALERT_FIELDS = (
    "rule_id", "rule_title", "severity", "techniques", "tags", "category",
    "timestamp", "computer", "channel", "event_id", "record_id",
    "user_name", "target_user_name", "process_name", "process_path",
    "process_command_line", "parent_process_name", "src_ip", "dst_ip",
    "file_path", "registry_key", "service_name", "task_name",
    "match_count", "correlation_key", "sample_record_ids", "source_file",
)


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    # SQLite has no built-in REGEXP; rules using |re depend on this.
    conn.create_function(
        "regexp", 2,
        lambda pattern, value: bool(
            value is not None and re.search(pattern, str(value), re.IGNORECASE)
        ),
    )
    return conn


def run_selection_rule(conn: sqlite3.Connection, rule: Rule,
                       limit: int) -> list[dict[str, Any]]:
    where, params = compile_rule(rule)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY timestamp LIMIT {limit}"
    LOG.debug("[%s] SQL: %s", rule.id, sql)

    alerts = []
    for row in conn.execute(sql, params):
        alerts.append(build_alert(rule, dict(row)))
    return alerts


def run_correlation_rule(conn: sqlite3.Connection, rule: Rule,
                         limit: int) -> list[dict[str, Any]]:
    """
    Sliding-window aggregation.

    event_count : N matching events per group within the window.
    value_count : N *distinct* values of `field` per group within the window.

    The distinction matters. Five failed logons for one account is noise;
    five failed logons against five different accounts from one IP is
    password spraying.
    """
    corr = rule.correlation or {}
    ctype = str(corr.get("type", "event_count")).lower()
    group_by = corr.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    for gb in group_by:
        if gb not in VALID_FIELDS:
            raise RuleError(f"[{rule.id}] correlation group_by field '{gb}' unknown")

    window = parse_timespan(corr.get("timespan", "5m"))
    cond = corr.get("condition") or {"gte": 5}
    threshold = int(cond.get("gte", cond.get("gt", 5)))
    if "gt" in cond and "gte" not in cond:
        threshold += 1

    count_field = corr.get("field")
    if ctype == "value_count":
        if not count_field:
            raise RuleError(f"[{rule.id}] value_count correlation needs 'field'")
        if count_field not in VALID_FIELDS:
            raise RuleError(f"[{rule.id}] correlation field '{count_field}' unknown")

    where, params = compile_rule(rule)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY timestamp"
    rows = [dict(r) for r in conn.execute(sql, params)]

    buckets: dict[tuple, list[dict[str, Any]]] = {}
    for row in rows:
        key = tuple(row.get(g) for g in group_by) if group_by else ("__all__",)
        buckets.setdefault(key, []).append(row)

    alerts: list[dict[str, Any]] = []
    for key, events in buckets.items():
        events = [e for e in events if parse_ts(e.get("timestamp"))]
        events.sort(key=lambda e: parse_ts(e["timestamp"]))

        start = 0
        for end in range(len(events)):
            if start > end:
                continue
            end_ts = parse_ts(events[end]["timestamp"])
            while start <= end and parse_ts(events[start]["timestamp"]) < end_ts - window:
                start += 1
            window_events = events[start:end + 1]
            if not window_events:
                continue

            if ctype == "value_count":
                measure = len({
                    e.get(count_field) for e in window_events
                    if e.get(count_field) not in (None, "")
                })
            else:
                measure = len(window_events)

            if measure >= threshold:
                alert = build_alert(rule, window_events[-1])
                alert["match_count"] = measure
                alert["correlation_key"] = "|".join(
                    f"{g}={key[i]}" for i, g in enumerate(group_by)
                ) or "all"
                alert["sample_record_ids"] = ",".join(
                    str(e.get("record_id")) for e in window_events[:10]
                )
                alert["timestamp"] = window_events[0]["timestamp"]
                alerts.append(alert)
                # Tumble rather than slide once a threshold is met. A sliding
                # window re-fires on every subsequent event in the burst, so a
                # 100-event brute force would raise ~96 duplicate alerts.
                start = end + 1
                if len(alerts) >= limit:
                    return alerts
    return alerts


def build_alert(rule: Rule, row: dict[str, Any]) -> dict[str, Any]:
    alert = {f: None for f in ALERT_FIELDS}
    alert.update(
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        techniques=",".join(rule.techniques) or None,
        tags=",".join(rule.tags) or None,
        source_file=rule.source_file,
        match_count=1,
    )
    for key in ALERT_FIELDS:
        if alert.get(key) is None and key in row:
            alert[key] = row[key]
    return alert


@dataclass
class EngineStats:
    rules_loaded: int = 0
    rules_run: int = 0
    rules_failed: int = 0
    rules_fired: int = 0
    alerts: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    by_technique: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def evaluate(conn: sqlite3.Connection, rules: Iterable[Rule], limit: int,
             stats: EngineStats) -> Iterator[dict[str, Any]]:
    for rule in rules:
        if not rule.enabled:
            LOG.debug("[%s] disabled, skipping", rule.id)
            continue
        try:
            found = (run_correlation_rule(conn, rule, limit) if rule.is_correlation
                     else run_selection_rule(conn, rule, limit))
        except (RuleError, sqlite3.Error) as exc:
            stats.rules_failed += 1
            stats.errors.append(f"{rule.id}: {exc}")
            LOG.error("Rule failed - %s", exc)
            continue

        stats.rules_run += 1
        if found:
            stats.rules_fired += 1
            stats.by_rule[rule.id] = len(found)
            LOG.info("%-9s %-42s %d", rule.severity.upper(), rule.title, len(found))
        for alert in found:
            stats.alerts += 1
            stats.by_severity[rule.severity] = stats.by_severity.get(rule.severity, 0) + 1
            for tech in rule.techniques:
                stats.by_technique[tech] = stats.by_technique.get(tech, 0) + 1
            yield alert


# ---------------------------------Output------------------------------------------


def write_alerts(alerts: list[dict[str, Any]], out_dir: Path) -> None:
    jsonl_path = out_dir / "alerts.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for alert in alerts:
            compact = {k: v for k, v in alert.items() if v not in (None, "")}
            handle.write(json.dumps(compact, ensure_ascii=False) + "\n")

    db_path = out_dir / "alerts.sqlite"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    cols = ", ".join(
        f'"{c}" {"INTEGER" if c == "match_count" else "TEXT"}' for c in ALERT_FIELDS
    )
    conn.execute(f"CREATE TABLE alerts ({cols})")
    conn.executemany(
        f'INSERT INTO alerts VALUES ({", ".join("?" * len(ALERT_FIELDS))})',
        [tuple(a[c] for c in ALERT_FIELDS) for a in alerts],
    )
    conn.execute("CREATE INDEX idx_sev ON alerts(severity)")
    conn.execute("CREATE INDEX idx_rule ON alerts(rule_id)")
    conn.execute("CREATE INDEX idx_ts ON alerts(timestamp)")
    conn.commit()
    conn.close()


def resolve_events_db(target: Path) -> Path:
    """Accept a parsed folder, a collection folder, or the .sqlite file itself."""
    target = target.expanduser().resolve()
    if target.is_file() and target.suffix == ".sqlite":
        return target
    for candidate in (target / "events.sqlite", target / "parsed" / "events.sqlite"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"No events.sqlite found at or under {target}. "
        f"Run parse_eventlogs.py with --format sqlite first."
    )


# ----------------------------------------CLI-----------------------------------


def main(argv: list[str] | None = None) -> int:
    script_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(
        description="Run YAML detection rules against a parsed event store.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("target", type=Path, nargs="?", default=Path.cwd(),
                    help="Parsed folder, collection folder, or events.sqlite")
    ap.add_argument("--rules", type=Path, default=script_dir / "rules",
                    help="Folder containing .yml rule files")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output folder (default: alongside events.sqlite)")
    ap.add_argument("--min-severity", default="informational",
                    choices=list(SEVERITY_ORDER),
                    help="Suppress rules below this severity")
    ap.add_argument("--rule-id", nargs="+", default=None,
                    help="Run only these rule ids")
    ap.add_argument("--limit", type=int, default=500,
                    help="Max alerts per rule")
    ap.add_argument("--list-rules", action="store_true",
                    help="Validate and list the rule set, then exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        rules = load_rules(args.rules.expanduser().resolve())
    except FileNotFoundError as exc:
        LOG.error("%s", exc)
        return 2

    stats = EngineStats(rules_loaded=len(rules))

    floor = SEVERITY_ORDER[args.min_severity]
    rules = [r for r in rules if SEVERITY_ORDER[r.severity] >= floor]
    if args.rule_id:
        wanted = set(args.rule_id)
        rules = [r for r in rules if r.id in wanted]

    if args.list_rules:
        LOG.info("%d rule(s) loaded from %s", stats.rules_loaded, args.rules)
        for rule in sorted(rules, key=lambda r: (-SEVERITY_ORDER[r.severity], r.id)):
            try:
                compile_rule(rule)
                status = "ok"
            except RuleError as exc:
                status = f"INVALID: {exc}"
            kind = "corr" if rule.is_correlation else "sel "
            LOG.info("  %-9s %s %-34s %-22s %s",
                     rule.severity, kind, rule.id,
                     ",".join(rule.techniques) or "-", status)
        return 0

    try:
        db_path = resolve_events_db(args.target)
    except FileNotFoundError as exc:
        LOG.error("%s", exc)
        return 2

    out_dir = (args.out or db_path.parent).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    LOG.info("Events   : %s", db_path)
    LOG.info("Rules    : %d enabled", len(rules))
    LOG.info("-" * 62)

    conn = connect(db_path)
    try:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = list(evaluate(conn, rules, args.limit, stats))
    finally:
        conn.close()

    alerts.sort(
        key=lambda a: (-SEVERITY_ORDER.get(a["severity"], 0), a["timestamp"] or "")
    )
    write_alerts(alerts, out_dir)

    report = {
        "detected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "events_database": str(db_path),
        "events_evaluated": total_events,
        "rules_folder": str(args.rules),
        "engine_version": "1.0.0",
        "rules_loaded": stats.rules_loaded,
        "rules_evaluated": stats.rules_run,
        "rules_failed": stats.rules_failed,
        "rules_fired": stats.rules_fired,
        "alerts_total": stats.alerts,
        "alerts_by_severity": dict(sorted(
            stats.by_severity.items(),
            key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))),
        "alerts_by_rule": dict(sorted(stats.by_rule.items(), key=lambda kv: -kv[1])),
        "alerts_by_technique": dict(sorted(stats.by_technique.items(),
                                           key=lambda kv: -kv[1])),
        "rule_errors": stats.errors,
    }
    (out_dir / "detection_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    LOG.info("-" * 62)
    LOG.info("Events evaluated : %d", total_events)
    LOG.info("Rules fired      : %d of %d", stats.rules_fired, stats.rules_run)
    LOG.info("Alerts           : %d  %s", stats.alerts,
             "  ".join(f"{k}={v}" for k, v in report["alerts_by_severity"].items()))
    if stats.rules_failed:
        LOG.warning("Rules failed     : %d (see detection_report.json)",
                    stats.rules_failed)
    LOG.info("Output           : %s", out_dir)
    LOG.info("-" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())

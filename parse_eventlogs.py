# Parsing the collected windows event logs

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

LOG = logging.getLogger("parser")

# ---------------------------------------Channel identity------------------------------------

CHANNEL_ALIASES: dict[str, str] = {
    "security": "security",
    "system": "system",
    "application": "application",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell_classic",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-winrm/operational": "winrm",
    "microsoft-windows-windows defender/operational": "defender",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "rdp_local",
}


def channel_key(channel: str) -> str:
    """Map a verbose channel name to a short, stable key used by the mappers."""
    if not channel:
        return "unknown"
    key = CHANNEL_ALIASES.get(channel.strip().lower())
    if key:
        return key
    # Unknown channel: derive something deterministic rather than dropping it.
    return channel.strip().lower().replace("/", "_").replace(" ", "_")


# -----------------------------------------Lookup tables----------------------------------

LOGON_TYPES: dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# Well-known SIDs that generate huge volumes of benign noise. Not filtered
# here - flagged so the detection layer can decide.
MACHINE_ACCOUNT_SUFFIX = "$"


@dataclass
class EventCategory:
    """Semantic grouping plus candidate ATT&CK data components."""

    name: str
    data_sources: tuple[str, ...] = ()


CAT_PROCESS = EventCategory("process_creation", ("DS0009:Process Creation",))
CAT_PROCESS_END = EventCategory("process_termination", ("DS0009:Process Termination",))
CAT_PROCESS_ACCESS = EventCategory("process_access", ("DS0009:OS API Execution",))
CAT_NETWORK = EventCategory("network_connection", ("DS0029:Network Connection Creation",))
CAT_DNS = EventCategory("dns_query", ("DS0029:Network Traffic Content",))
CAT_FILE = EventCategory("file_event", ("DS0022:File Creation",))
CAT_REGISTRY = EventCategory("registry_event", ("DS0024:Windows Registry Key Modification",))
CAT_IMAGE_LOAD = EventCategory("image_load", ("DS0011:Module Load",))
CAT_LOGON = EventCategory("authentication", ("DS0028:Logon Session Creation",))
CAT_LOGOFF = EventCategory("logoff", ("DS0028:Logon Session Creation",))
CAT_ACCOUNT = EventCategory("account_management", ("DS0002:User Account Creation",))
CAT_GROUP = EventCategory("group_management", ("DS0036:Group Modification",))
CAT_SERVICE = EventCategory("service_install", ("DS0019:Service Creation",))
CAT_TASK = EventCategory("scheduled_task", ("DS0003:Scheduled Job Creation",))
CAT_SCRIPT = EventCategory("script_execution", ("DS0012:Script Execution",))
CAT_LOG_CLEARED = EventCategory("log_cleared", ("DS0015:Application Log Content",))
CAT_DEFENDER = EventCategory("av_detection", ("DS0013:Malware Detection",))
CAT_SHARE = EventCategory("share_access", ("DS0033:Network Share Access",))
CAT_RDP = EventCategory("remote_session", ("DS0028:Logon Session Creation",))
CAT_OTHER = EventCategory("other", ())


# -------------------------------------Field access helpers--------------------------------------

EMPTY_VALUES = {None, "", "-", "N/A", "null"}


def pick(data: dict[str, Any], *names: str, default: Any = None) -> Any:
    """First non-empty value among `names`. Case-insensitive fallback."""
    for name in names:
        if name in data:
            value = data[name]
            if value not in EMPTY_VALUES:
                return value
    lowered = {k.lower(): v for k, v in data.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in EMPTY_VALUES:
            return value
    return default


def to_int(value: Any) -> int | None:
    """Windows mixes decimal and hex ('0x1f4') PIDs across channels."""
    if value in EMPTY_VALUES:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (ValueError, TypeError):
        return None


def basename(path: Any) -> str | None:
    if path in EMPTY_VALUES:
        return None
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1]


def split_account(value: Any) -> tuple[str | None, str | None]:
    """Split DOMAIN\\user or user@domain into (domain, user)."""
    if value in EMPTY_VALUES:
        return None, None
    text = str(value)
    if "\\" in text:
        domain, _, user = text.partition("\\")
        return domain or None, user or None
    if "@" in text:
        user, _, domain = text.partition("@")
        return domain or None, user or None
    return None, text


# ----------------------------------------Per-event mappers-----------------------------------

# Each mapper receives the raw EventData dict and returns normalised fields.
# Keys not returned stay None. Mappers must never raise on missing fields -
# real-world logs are frequently incomplete.

Mapper = Callable[[dict[str, Any]], dict[str, Any]]
MAPPERS: dict[tuple[str, int], tuple[EventCategory, Mapper]] = {}


def register(channel: str, *event_ids: int, category: EventCategory = CAT_OTHER):
    def decorator(fn: Mapper) -> Mapper:
        for eid in event_ids:
            MAPPERS[(channel, eid)] = (category, fn)
        return fn

    return decorator


# -------------------------------- Sysmon -----------------------------------


@register("sysmon", 1, category=CAT_PROCESS)
def _sysmon_process_create(d: dict[str, Any]) -> dict[str, Any]:
    domain, user = split_account(pick(d, "User"))
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "process_command_line": pick(d, "CommandLine"),
        "process_working_dir": pick(d, "CurrentDirectory"),
        "process_integrity_level": pick(d, "IntegrityLevel"),
        "process_hashes": pick(d, "Hashes"),
        "parent_process_guid": pick(d, "ParentProcessGuid"),
        "parent_process_id": to_int(pick(d, "ParentProcessId")),
        "parent_process_path": pick(d, "ParentImage"),
        "parent_process_name": basename(pick(d, "ParentImage")),
        "parent_command_line": pick(d, "ParentCommandLine"),
        "user_name": user,
        "user_domain": domain,
        "logon_id": pick(d, "LogonId"),
    }


@register("sysmon", 5, category=CAT_PROCESS_END)
def _sysmon_process_end(d: dict[str, Any]) -> dict[str, Any]:
    domain, user = split_account(pick(d, "User"))
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "user_name": user,
        "user_domain": domain,
    }


@register("sysmon", 3, category=CAT_NETWORK)
def _sysmon_network(d: dict[str, Any]) -> dict[str, Any]:
    domain, user = split_account(pick(d, "User"))
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "src_ip": pick(d, "SourceIp"),
        "src_port": to_int(pick(d, "SourcePort")),
        "src_host": pick(d, "SourceHostname"),
        "dst_ip": pick(d, "DestinationIp"),
        "dst_port": to_int(pick(d, "DestinationPort")),
        "dst_host": pick(d, "DestinationHostname"),
        "protocol": pick(d, "Protocol"),
        "user_name": user,
        "user_domain": domain,
    }


@register("sysmon", 22, category=CAT_DNS)
def _sysmon_dns(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "dns_query": pick(d, "QueryName"),
        "dns_result": pick(d, "QueryResults"),
        "dns_status": pick(d, "QueryStatus"),
    }


@register("sysmon", 11, 23, 26, category=CAT_FILE)
def _sysmon_file(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "file_path": pick(d, "TargetFilename"),
        "file_name": basename(pick(d, "TargetFilename")),
        "process_hashes": pick(d, "Hashes"),
    }


@register("sysmon", 12, 13, 14, category=CAT_REGISTRY)
def _sysmon_registry(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "registry_key": pick(d, "TargetObject"),
        "registry_value": pick(d, "Details", "NewName"),
        "registry_operation": pick(d, "EventType"),
    }


@register("sysmon", 7, category=CAT_IMAGE_LOAD)
def _sysmon_image_load(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_guid": pick(d, "ProcessGuid"),
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "Image"),
        "process_name": basename(pick(d, "Image")),
        "file_path": pick(d, "ImageLoaded"),
        "file_name": basename(pick(d, "ImageLoaded")),
        "signature_status": pick(d, "SignatureStatus"),
        "signer": pick(d, "Signature"),
        "process_hashes": pick(d, "Hashes"),
    }


@register("sysmon", 8, 10, category=CAT_PROCESS_ACCESS)
def _sysmon_process_access(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_guid": pick(d, "SourceProcessGuid", "SourceProcessGUID"),
        "process_id": to_int(pick(d, "SourceProcessId")),
        "process_path": pick(d, "SourceImage"),
        "process_name": basename(pick(d, "SourceImage")),
        "target_process_id": to_int(pick(d, "TargetProcessId")),
        "target_process_path": pick(d, "TargetImage"),
        "target_process_name": basename(pick(d, "TargetImage")),
        "granted_access": pick(d, "GrantedAccess"),
        "call_trace": pick(d, "CallTrace"),
    }


# ---------------------------- Security -------------------------------------


@register("security", 4688, category=CAT_PROCESS)
def _sec_process_create(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_id": to_int(pick(d, "NewProcessId")),
        "process_path": pick(d, "NewProcessName"),
        "process_name": basename(pick(d, "NewProcessName")),
        "process_command_line": pick(d, "CommandLine"),
        "process_integrity_level": pick(d, "MandatoryLabel"),
        "parent_process_id": to_int(pick(d, "ProcessId")),
        "parent_process_path": pick(d, "ParentProcessName"),
        "parent_process_name": basename(pick(d, "ParentProcessName")),
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "target_user_name": pick(d, "TargetUserName"),
    }


@register("security", 4689, category=CAT_PROCESS_END)
def _sec_process_end(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_id": to_int(pick(d, "ProcessId")),
        "process_path": pick(d, "ProcessName"),
        "process_name": basename(pick(d, "ProcessName")),
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "exit_status": pick(d, "Status"),
    }


@register("security", 4624, 4625, 4648, category=CAT_LOGON)
def _sec_logon(d: dict[str, Any]) -> dict[str, Any]:
    logon_type = to_int(pick(d, "LogonType"))
    return {
        "target_user_name": pick(d, "TargetUserName"),
        "target_user_domain": pick(d, "TargetDomainName"),
        "target_user_sid": pick(d, "TargetUserSid"),
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "TargetLogonId", "SubjectLogonId"),
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPES.get(logon_type) if logon_type else None,
        "auth_package": pick(d, "AuthenticationPackageName", "LmPackageName"),
        "workstation": pick(d, "WorkstationName"),
        "src_ip": pick(d, "IpAddress"),
        "src_port": to_int(pick(d, "IpPort")),
        "process_path": pick(d, "ProcessName"),
        "process_name": basename(pick(d, "ProcessName")),
        "failure_reason": pick(d, "Status", "SubStatus"),
        "elevated_token": pick(d, "ElevatedToken"),
    }


@register("security", 4634, 4647, category=CAT_LOGOFF)
def _sec_logoff(d: dict[str, Any]) -> dict[str, Any]:
    logon_type = to_int(pick(d, "LogonType"))
    return {
        "target_user_name": pick(d, "TargetUserName"),
        "target_user_domain": pick(d, "TargetDomainName"),
        "target_user_sid": pick(d, "TargetUserSid"),
        "logon_id": pick(d, "TargetLogonId"),
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPES.get(logon_type) if logon_type else None,
    }


@register("security", 4672, category=CAT_LOGON)
def _sec_special_privileges(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "target_user_name": pick(d, "SubjectUserName"),
        "target_user_domain": pick(d, "SubjectDomainName"),
        "target_user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "privileges": pick(d, "PrivilegeList"),
    }


@register("security", 4720, 4722, 4724, 4726, 4738, 4740, category=CAT_ACCOUNT)
def _sec_account_mgmt(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "target_user_name": pick(d, "TargetUserName"),
        "target_user_domain": pick(d, "TargetDomainName"),
        "target_user_sid": pick(d, "TargetSid", "TargetUserSid"),
    }


@register("security", 4728, 4732, 4756, 4729, 4733, 4757, category=CAT_GROUP)
def _sec_group_mgmt(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "target_user_name": pick(d, "MemberName"),
        "target_user_sid": pick(d, "MemberSid"),
        "group_name": pick(d, "TargetUserName"),
        "group_domain": pick(d, "TargetDomainName"),
    }


@register("security", 4698, 4699, 4700, 4701, 4702, category=CAT_TASK)
def _sec_scheduled_task(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "task_name": pick(d, "TaskName"),
        "task_content": pick(d, "TaskContent"),
    }


@register("security", 5140, 5145, category=CAT_SHARE)
def _sec_share(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
        "src_ip": pick(d, "IpAddress"),
        "src_port": to_int(pick(d, "IpPort")),
        "share_name": pick(d, "ShareName"),
        "file_path": pick(d, "ShareLocalPath", "RelativeTargetName"),
    }


@register("security", 1102, category=CAT_LOG_CLEARED)
def _sec_log_cleared(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "user_domain": pick(d, "SubjectDomainName"),
        "user_sid": pick(d, "SubjectUserSid"),
        "logon_id": pick(d, "SubjectLogonId"),
    }


# -------------------------------- System -----------------------------------


@register("system", 7045, category=CAT_SERVICE)
def _sys_service_install(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": pick(d, "ServiceName"),
        "service_path": pick(d, "ImagePath"),
        "service_type": pick(d, "ServiceType"),
        "service_start_type": pick(d, "StartType"),
        "target_user_name": pick(d, "AccountName"),
    }


@register("system", 7040, category=CAT_SERVICE)
def _sys_service_change(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": pick(d, "param1", "ServiceName"),
        "service_start_type": pick(d, "param3"),
    }


@register("system", 104, category=CAT_LOG_CLEARED)
def _sys_log_cleared(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_name": pick(d, "SubjectUserName"),
        "target_channel": pick(d, "Channel"),
    }


# ------------------------------ PowerShell ---------------------------------


@register("powershell", 4104, category=CAT_SCRIPT)
def _ps_script_block(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "script_block_text": pick(d, "ScriptBlockText"),
        "script_block_id": pick(d, "ScriptBlockId"),
        "file_path": pick(d, "Path"),
        "message_number": to_int(pick(d, "MessageNumber")),
        "message_total": to_int(pick(d, "MessageTotal")),
    }


@register("powershell", 4103, category=CAT_SCRIPT)
def _ps_module_logging(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "script_block_text": pick(d, "Payload"),
        "command_context": pick(d, "ContextInfo"),
        "user_name": pick(d, "UserId"),
    }


@register("powershell_classic", 400, 403, 800, category=CAT_SCRIPT)
def _ps_classic(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "script_block_text": pick(d, "param3", "Payload"),
        "host_application": pick(d, "param2"),
    }


# ------------------- Defender / Task Scheduler / RDP -----------------------


@register("defender", 1006, 1007, 1116, 1117, category=CAT_DEFENDER)
def _defender(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "threat_name": pick(d, "Threat Name", "ThreatName"),
        "threat_severity": pick(d, "Severity Name", "SeverityName"),
        "file_path": pick(d, "Path"),
        "process_path": pick(d, "Process Name", "ProcessName"),
        "action_taken": pick(d, "Action Name", "ActionName"),
        "user_name": pick(d, "Detection User", "User"),
    }


@register("taskscheduler", 106, 140, 141, 200, 201, category=CAT_TASK)
def _taskscheduler(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_name": pick(d, "TaskName"),
        "user_name": pick(d, "UserName", "UserContext"),
        "process_path": pick(d, "ActionName", "Path"),
        "process_id": to_int(pick(d, "ProcessID")),
    }


@register("rdp_local", 21, 22, 23, 24, 25, category=CAT_RDP)
def _rdp_local(d: dict[str, Any]) -> dict[str, Any]:
    domain, user = split_account(pick(d, "User"))
    return {
        "target_user_name": user,
        "target_user_domain": domain,
        "src_ip": pick(d, "Address"),
        "session_id": to_int(pick(d, "SessionID")),
    }


# ------------------------------------Output schema---------------------------------------

COLUMNS: tuple[str, ...] = (
    # identity
    "timestamp", "record_id", "event_id", "channel", "channel_key", "provider",
    "computer", "level", "category", "attack_data_sources",
    # actor
    "user_name", "user_domain", "user_sid", "logon_id",
    "target_user_name", "target_user_domain", "target_user_sid",
    "group_name", "group_domain", "privileges",
    # process
    "process_id", "process_guid", "process_name", "process_path",
    "process_command_line", "process_working_dir", "process_integrity_level",
    "process_hashes", "exit_status",
    "parent_process_id", "parent_process_guid", "parent_process_name",
    "parent_process_path", "parent_command_line",
    "target_process_id", "target_process_name", "target_process_path",
    "granted_access", "call_trace",
    # authentication
    "logon_type", "logon_type_name", "auth_package", "workstation",
    "elevated_token", "failure_reason", "session_id",
    # network
    "src_ip", "src_port", "src_host", "dst_ip", "dst_port", "dst_host",
    "protocol", "dns_query", "dns_result", "dns_status", "share_name",
    # file / registry
    "file_path", "file_name", "registry_key", "registry_value",
    "registry_operation", "signature_status", "signer",
    # service / task / script
    "service_name", "service_path", "service_type", "service_start_type",
    "task_name", "task_content", "script_block_text", "script_block_id",
    "message_number", "message_total", "command_context", "host_application",
    "target_channel",
    # defender
    "threat_name", "threat_severity", "action_taken",
    # provenance
    "is_machine_account", "mapped", "source_file", "event_data", "message",
)

TEXT_COLUMNS = set(COLUMNS)
INT_COLUMNS = {
    "record_id", "event_id", "process_id", "parent_process_id",
    "target_process_id", "src_port", "dst_port", "logon_type", "session_id",
    "message_number", "message_total", "is_machine_account", "mapped",
}


# ------------------------------------Core parsing---------------------------------------


@dataclass
class ParseStats:
    total: int = 0
    mapped: int = 0
    unmapped: int = 0
    errors: int = 0
    by_channel: dict[str, int] = field(default_factory=dict)
    by_event: dict[str, int] = field(default_factory=dict)
    unmapped_events: dict[str, int] = field(default_factory=dict)
    error_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total,
            "normalised": self.mapped,
            "passthrough_only": self.unmapped,
            "parse_errors": self.errors,
            "events_by_channel": dict(sorted(self.by_channel.items(),
                                             key=lambda kv: -kv[1])),
            "events_by_id": dict(sorted(self.by_event.items(),
                                        key=lambda kv: -kv[1])),
            "unmapped_event_ids": dict(sorted(self.unmapped_events.items(),
                                              key=lambda kv: -kv[1])),
            "error_samples": self.error_samples[:20],
        }


def parse_timestamp(value: Any) -> str | None:
    """Normalise to ISO-8601 UTC with a trailing Z."""
    if value in EMPTY_VALUES:
        return None
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            return text  # keep the original rather than losing the value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def normalise(raw: dict[str, Any], source_file: str) -> dict[str, Any]:
    """Convert one collector record into the common schema."""
    data = raw.get("EventData") or {}
    if not isinstance(data, dict):
        data = {"_value": data}

    channel = raw.get("Channel") or ""
    ckey = channel_key(channel)
    eid = to_int(raw.get("EventId"))

    row: dict[str, Any] = {col: None for col in COLUMNS}
    row.update(
        timestamp=parse_timestamp(raw.get("TimeCreated")),
        record_id=to_int(raw.get("RecordId")),
        event_id=eid,
        channel=channel,
        channel_key=ckey,
        provider=raw.get("Provider"),
        computer=raw.get("Computer"),
        level=raw.get("Level"),
        user_sid=raw.get("UserSid"),
        process_id=to_int(raw.get("ProcessId")),
        message=raw.get("Message"),
        source_file=source_file,
        event_data=json.dumps(data, ensure_ascii=False, sort_keys=True),
        mapped=0,
        category=CAT_OTHER.name,
        attack_data_sources=None,
    )

    entry = MAPPERS.get((ckey, eid)) if eid is not None else None
    if entry:
        category, mapper = entry
        mapped_fields = mapper(data)
        for key, value in mapped_fields.items():
            if key in row and value not in EMPTY_VALUES:
                row[key] = value
        row["category"] = category.name
        row["attack_data_sources"] = ",".join(category.data_sources) or None
        row["mapped"] = 1

    # Machine accounts (NAME$) dominate 4624/4672 volume in domain environments.
    account = row.get("target_user_name") or row.get("user_name")
    row["is_machine_account"] = int(
        bool(account) and str(account).endswith(MACHINE_ACCOUNT_SUFFIX)
    )

    # Normalise unspecified IPv6/IPv4 placeholders that Windows emits.
    for ip_field in ("src_ip", "dst_ip"):
        if row.get(ip_field) in {"::", "0.0.0.0", "::1"} and row[ip_field] != "::1":
            row[ip_field] = None

    return row


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8-sig") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            yield lineno, json.loads(line)


def iter_collection(
    case_dir: Path,
    channels: set[str] | None = None,
    stats: ParseStats | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield normalised rows from every .jsonl file in the collection."""
    jsonl_dir = case_dir / "jsonl"
    if not jsonl_dir.is_dir():
        raise FileNotFoundError(
            f"No 'jsonl' folder in {case_dir}. Re-run the collector with "
            f"-Format JSONL or -Format All."
        )

    files = sorted(jsonl_dir.glob("*.jsonl"))
    if not files:
        raise FileNotFoundError(f"No .jsonl files found in {jsonl_dir}")

    for jsonl_file in files:
        LOG.info("Reading %s", jsonl_file.name)
        for lineno, raw in iter_jsonl(jsonl_file):
            try:
                row = normalise(raw, jsonl_file.name)
            except Exception as exc:  # noqa: BLE001 - never abort the batch
                if stats:
                    stats.errors += 1
                    stats.error_samples.append(
                        f"{jsonl_file.name}:{lineno}: {type(exc).__name__}: {exc}"
                    )
                continue

            if channels and row["channel_key"] not in channels:
                continue

            if stats:
                stats.total += 1
                stats.by_channel[row["channel_key"]] = (
                    stats.by_channel.get(row["channel_key"], 0) + 1
                )
                label = f"{row['channel_key']}/{row['event_id']}"
                stats.by_event[label] = stats.by_event.get(label, 0) + 1
                if row["mapped"]:
                    stats.mapped += 1
                else:
                    stats.unmapped += 1
                    stats.unmapped_events[label] = (
                        stats.unmapped_events.get(label, 0) + 1
                    )

            yield row


# -------------------------------------Integrity verification--------------------------------------


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def verify_collection(case_dir: Path) -> dict[str, Any]:
    """Re-hash every file and compare against the collector's manifest."""
    manifest_path = case_dir / "manifest.json"
    if not manifest_path.is_file():
        return {"verified": False, "reason": "manifest.json not found"}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    entries = manifest.get("Files") or []
    if not entries:
        return {"verified": False, "reason": "manifest contains no file hashes"}

    matched, mismatched, missing = [], [], []
    for entry in entries:
        rel = str(entry.get("Path", "")).replace("\\", "/")
        target = case_dir / rel
        if not target.is_file():
            missing.append(rel)
            continue
        actual = sha256_file(target)
        expected = str(entry.get("SHA256", "")).upper()
        (matched if actual == expected else mismatched).append(rel)

    return {
        "verified": not mismatched and not missing,
        "collection_id": manifest.get("CollectionId"),
        "hostname": manifest.get("Hostname"),
        "window_start_utc": manifest.get("WindowStartUtc"),
        "window_end_utc": manifest.get("WindowEndUtc"),
        "files_matched": len(matched),
        "files_mismatched": mismatched,
        "files_missing": missing,
    }


# ------------------------------------Writers---------------------------------------


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = path.open("w", encoding="utf-8")

    def write(self, row: dict[str, Any]) -> None:
        compact = {k: v for k, v in row.items() if v not in (None, "")}
        self._handle.write(json.dumps(compact, ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._handle.close()


class CsvWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = path.open("w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._handle, fieldnames=list(COLUMNS))
        self._writer.writeheader()

    def write(self, row: dict[str, Any]) -> None:
        safe = {
            k: (str(v).replace("\r", " ").replace("\n", " ")
                if isinstance(v, str) else v)
            for k, v in row.items()
        }
        self._writer.writerow(safe)

    def close(self) -> None:
        self._handle.close()


class SqliteWriter:
    """Writes to SQLite so the detection layer can express rules as SQL."""

    BATCH = 1000

    def __init__(self, path: Path) -> None:
        if path.exists():
            path.unlink()
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        cols = ", ".join(
            f'"{c}" {"INTEGER" if c in INT_COLUMNS else "TEXT"}' for c in COLUMNS
        )
        self.conn.execute(f"CREATE TABLE events ({cols})")
        quoted = ", ".join('"%s"' % c for c in COLUMNS)
        placeholders = ", ".join("?" * len(COLUMNS))
        self._sql = f"INSERT INTO events ({quoted}) VALUES ({placeholders})"
        self._buffer: list[tuple] = []

    def write(self, row: dict[str, Any]) -> None:
        self._buffer.append(tuple(
            json.dumps(row[c], ensure_ascii=False)
            if isinstance(row[c], (dict, list)) else row[c]
            for c in COLUMNS
        ))
        if len(self._buffer) >= self.BATCH:
            self._flush()

    def _flush(self) -> None:
        if self._buffer:
            self.conn.executemany(self._sql, self._buffer)
            self._buffer.clear()

    def close(self) -> None:
        self._flush()
        for index_sql in (
            "CREATE INDEX idx_ts ON events(timestamp)",
            "CREATE INDEX idx_eid ON events(channel_key, event_id)",
            "CREATE INDEX idx_cat ON events(category)",
            "CREATE INDEX idx_proc ON events(process_name)",
            "CREATE INDEX idx_pproc ON events(parent_process_name)",
            "CREATE INDEX idx_user ON events(target_user_name)",
            "CREATE INDEX idx_dst ON events(dst_ip)",
        ):
            self.conn.execute(index_sql)
        self.conn.commit()
        self.conn.close()


# -----------------------------------Entry point----------------------------------------


def run(
    case_dir: Path,
    out_dir: Path,
    formats: Iterable[str],
    channels: set[str] | None,
    verify: bool,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    integrity: dict[str, Any] = {"verified": None, "reason": "skipped"}
    if verify:
        LOG.info("Verifying collection integrity...")
        integrity = verify_collection(case_dir)
        if integrity.get("verified"):
            LOG.info("Integrity OK (%s files)", integrity.get("files_matched"))
        else:
            LOG.warning("Integrity check did not pass: %s", integrity)

    writers = []
    formats = set(formats)
    if "jsonl" in formats:
        writers.append(JsonlWriter(out_dir / "events.jsonl"))
    if "csv" in formats:
        writers.append(CsvWriter(out_dir / "events.csv"))
    if "sqlite" in formats:
        writers.append(SqliteWriter(out_dir / "events.sqlite"))

    stats = ParseStats()
    try:
        for row in iter_collection(case_dir, channels=channels, stats=stats):
            for writer in writers:
                writer.write(row)
    finally:
        for writer in writers:
            writer.close()

    report = {
        "parsed_at_utc": datetime.now(timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collection_dir": str(case_dir),
        "output_dir": str(out_dir),
        "parser_version": "1.0.0",
        "integrity": integrity,
        "statistics": stats.to_dict(),
        "outputs": [str(w.path if hasattr(w, "path") else "events.sqlite")
                    for w in writers],
    }
    (out_dir / "parse_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Parse and normalise a Windows Event Log collection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("collection", type=Path,
                    help="Collection folder produced by Collect-WinEventLogs.ps1")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output folder (default: <collection>/parsed)")
    ap.add_argument("--format", nargs="+", default=["jsonl", "sqlite"],
                    choices=["jsonl", "csv", "sqlite"],
                    help="Output formats")
    ap.add_argument("--channels", nargs="+", default=None,
                    help="Restrict to channel keys, e.g. sysmon security powershell")
    ap.add_argument("--no-verify", action="store_true",
                    help="Skip SHA-256 integrity verification")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    case_dir: Path = args.collection.expanduser().resolve()
    if not case_dir.is_dir():
        LOG.error("Collection folder not found: %s", case_dir)
        return 2

    out_dir: Path = (args.out or case_dir / "parsed").expanduser().resolve()

    try:
        report = run(
            case_dir=case_dir,
            out_dir=out_dir,
            formats=args.format,
            channels=set(args.channels) if args.channels else None,
            verify=not args.no_verify,
        )
    except FileNotFoundError as exc:
        LOG.error("%s", exc)
        return 2

    st = report["statistics"]
    LOG.info("-" * 58)
    LOG.info("Events parsed   : %s", st["total_events"])
    LOG.info("Normalised      : %s", st["normalised"])
    LOG.info("Passthrough     : %s", st["passthrough_only"])
    LOG.info("Errors          : %s", st["parse_errors"])
    LOG.info("Output          : %s", out_dir)
    if st["unmapped_event_ids"]:
        top = list(st["unmapped_event_ids"].items())[:5]
        LOG.info("Top unmapped    : %s",
                 ", ".join(f"{k} ({v})" for k, v in top))
    LOG.info("-" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
from __future__ import annotations
import getpass
import platform
from .common import PesdEvent, hostname, now_epoch_ms, new_event_id, JsonlRotatingWriter

DEFAULT_LOG = r"C:\ProgramData\PESD\pesd-events.jsonl"

def _writer(log_path: str) -> JsonlRotatingWriter:
    return JsonlRotatingWriter(log_path)

def emit_high_priv_token(log_path: str = DEFAULT_LOG,
                         result: str = "success",
                         src_ip: str = "") -> str:
    ev = PesdEvent(
        event_id=new_event_id(),
        ts_ms=now_epoch_ms(),
        host=hostname(),
        os_family="windows",
        event_type="high_privilege_token",
        severity="high",
        user=getpass.getuser(),
        target_user=getpass.getuser(),
        action="special_privileges_assigned",
        result=result,
        src_ip=src_ip,
        command="",
        details={"platform": platform.platform(), "hint": "Analogous to 4672"},
    )
    _writer(log_path).write_line(ev.to_json())
    return ev.event_id

from __future__ import annotations
import getpass
import os
from .common import PesdEvent, hostname, now_epoch_ms, new_event_id, JsonlRotatingWriter

DEFAULT_LOG = "/tmp/pesd/pesd-events.jsonl"

def _writer(log_path: str) -> JsonlRotatingWriter:
    return JsonlRotatingWriter(log_path)

def emit_sudo_attempt(log_path: str = DEFAULT_LOG,
                      target_user: str = "root",
                      command: str = "id",
                      result: str = "fail",
                      src_ip: str = "") -> str:
    ev = PesdEvent(
        event_id=new_event_id(),
        ts_ms=now_epoch_ms(),
        host=hostname(),
        os_family="linux",
        event_type="sudo_attempt",
        severity="high" if result == "success" else "medium",
        user=getpass.getuser(),
        target_user=target_user,
        action="sudo",
        result=result,
        src_ip=src_ip,
        command=command,
        details={"uid": os.getuid(), "euid": os.geteuid(), "cwd": os.getcwd()},
    )
    _writer(log_path).write_line(ev.to_json())
    return ev.event_id

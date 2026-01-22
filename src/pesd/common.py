from __future__ import annotations

import json
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass, asdict, field
from typing import Any, Dict
from logging.handlers import RotatingFileHandler
import logging

SAFE_TEXT = re.compile(r"[^\x09\x0A\x0D\x20-\x7E]")

def hostname() -> str:
    return socket.gethostname()

def now_epoch_ms() -> int:
    return int(time.time() * 1000)

def new_event_id() -> str:
    return str(uuid.uuid4())

def sanitize_text(s: str, max_len: int = 500) -> str:
    if s is None:
        return ""
    s = str(s)
    s = SAFE_TEXT.sub("?", s)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s[:max_len]

@dataclass
class PesdEvent:
    schema: str = "pesd.v1"
    event_id: str = ""
    ts_ms: int = 0
    host: str = ""
    os_family: str = ""
    event_type: str = ""
    severity: str = "medium"
    user: str = ""
    target_user: str = ""
    action: str = ""
    result: str = "unknown"
    src_ip: str = ""
    command: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def normalize(self) -> "PesdEvent":
        self.user = sanitize_text(self.user)
        self.target_user = sanitize_text(self.target_user)
        self.action = sanitize_text(self.action)
        self.result = sanitize_text(self.result)
        self.src_ip = sanitize_text(self.src_ip)
        self.command = sanitize_text(self.command)
        return self

    def to_json(self) -> str:
        self.normalize()
        return json.dumps(asdict(self), ensure_ascii=False)

class JsonlRotatingWriter:
    def __init__(self, path: str, max_bytes: int = 2_000_000, backup_count: int = 5):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.logger = logging.getLogger(f"pesd-jsonl:{path}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        handler = RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.handlers = [handler]

    def write_line(self, line: str) -> None:
        self.logger.info(line)

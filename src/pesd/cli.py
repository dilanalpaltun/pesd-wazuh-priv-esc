from __future__ import annotations
import argparse
import os
from .linux_emitter import emit_sudo_attempt
from .windows_emitter import emit_high_priv_token

def main() -> int:
    p = argparse.ArgumentParser(prog="pesd", description="PESD Event Emitter CLI")
    p.add_argument("--os", choices=["linux", "windows"], required=True)
    p.add_argument("--log", required=True)

    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("sudo")
    s1.add_argument("--result", choices=["success", "fail"], default="fail")
    s1.add_argument("--command", default="id")

    w1 = sub.add_parser("token")
    w1.add_argument("--result", choices=["success", "fail"], default="success")

    args = p.parse_args()
    os.makedirs(os.path.dirname(args.log), exist_ok=True)

    if args.os == "linux" and args.cmd == "sudo":
        eid = emit_sudo_attempt(args.log, command=args.command, result=args.result)
    elif args.os == "windows" and args.cmd == "token":
        eid = emit_high_priv_token(args.log, result=args.result)
    else:
        raise SystemExit("Invalid combination")

    print(f"OK event_id={eid}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline pattern tests for block_destructive.py (no Claude Code required)."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("block_destructive", ROOT / "block_destructive.py")
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(mod)

BLOCK = [
    "rm -rf /tmp/x",
    "rm -fr ./dist",
    "sudo rm -rf /var/cache/tmp",
    "echo hi && rm -rf build",
    "DROP TABLE users;",
    "drop table if exists sessions",
    "TRUNCATE TABLE cache;",
    "truncate audit_log",
    "git push --force origin main",
    "git push -f origin HEAD",
    "git push --force-with-lease origin main",
    "DELETE FROM sessions;",
    "delete from users",
    "sqlite3 db.sqlite \"DELETE FROM kv\"",
]

ALLOW = [
    "ls -la",
    "rm file.txt",
    "rm -f single.txt",
    "git push origin main",
    "git status",
    "DELETE FROM users WHERE id = 1;",
    "delete from sessions where expired = 1",
    "SELECT * FROM users;",
    "npm test",
    "echo DROP TABLE is just text in a comment? wait — DROP TABLE users",  # still blocks — contains DROP TABLE
]


def run_hook(command: str, cwd: str = "/tmp/proj") -> tuple[int, str]:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    }
    old_in, old_out = sys.stdin, sys.stdout
    buf = io.StringIO()
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = buf
    try:
        # Point log into temp so we don't write home during CI
        with tempfile.TemporaryDirectory() as td:
            mod.LOG_PATH = Path(td) / "blocked.log"
            code = mod.main()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    return code, buf.getvalue()


def main() -> int:
    failed = 0
    for cmd in BLOCK:
        code, out = run_hook(cmd)
        ok = "permissionDecision" in out and '"deny"' in out
        if not ok:
            print(f"FAIL block: {cmd!r} -> {out!r}")
            failed += 1
        else:
            print(f"OK   block: {cmd!r}")

    # ALLOW except the intentional DROP TABLE string case which should block
    for cmd in ALLOW:
        code, out = run_hook(cmd)
        expect_deny = "DROP TABLE" in cmd.upper() and "SELECT" not in cmd.upper()
        # the last ALLOW entry intentionally contains DROP TABLE → deny
        if cmd.startswith("echo DROP"):
            expect_deny = True
        denied = "permissionDecision" in out and '"deny"' in out
        if expect_deny and not denied:
            print(f"FAIL expect deny: {cmd!r}")
            failed += 1
        elif not expect_deny and denied:
            print(f"FAIL allow: {cmd!r} -> {out!r}")
            failed += 1
        else:
            print(f"OK   {'deny ' if expect_deny else 'allow'}: {cmd!r}")

    # Log line shape (drive hook with LOG_PATH already set)
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "blocked.log"
        mod.LOG_PATH = log
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/z"},
            "cwd": "/proj/demo",
        }
        old_in, old_out = sys.stdin, sys.stdout
        buf = io.StringIO()
        sys.stdin = io.StringIO(json.dumps(payload))
        sys.stdout = buf
        try:
            mod.main()
        finally:
            sys.stdin, sys.stdout = old_in, old_out
        line = log.read_text().strip()
        parts = line.split("\t")
        if len(parts) != 4 or parts[3] != "/proj/demo" or "rm -rf" not in parts[2]:
            print(f"FAIL log shape: {line!r}")
            failed += 1
        else:
            print(f"OK   log: {line}")

    print("---")
    print("PASS" if failed == 0 else f"FAILED={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

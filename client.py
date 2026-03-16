#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple

CONFIG_PATH = Path(os.getenv("SECURITY_CLIENT_CONFIG", Path.home() / ".config" / "aum-client.env"))


def load_config() -> None:
    """Load config file into environment variables (does not overwrite existing values)."""
    if not CONFIG_PATH.exists():
        return
    for line in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def first_run_init() -> bool:
    """Generate credentials on first run. Returns True if this was a first-run setup."""
    load_config()

    has_token = bool(os.getenv("SECURITY_API_TOKEN", "").strip())
    has_secret = bool(os.getenv("SECURITY_HMAC_SECRET", "").strip())

    if has_token and has_secret:
        return False

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    token = os.getenv("SECURITY_API_TOKEN", "").strip() or secrets.token_hex(32)
    secret = os.getenv("SECURITY_HMAC_SECRET", "").strip() or secrets.token_hex(48)
    node_id = os.getenv("SECURITY_NODE_ID", socket.gethostname())
    server_url = os.getenv("SECURITY_SERVER_URL", "http://127.0.0.1:55000/api/node-report")

    config_lines = [
        "# AUM client configuration — generated on first run",
        "# Keep this file private; it contains secret credentials.",
        "",
        f"SECURITY_API_TOKEN={token}",
        f"SECURITY_HMAC_SECRET={secret}",
        f"SECURITY_NODE_ID={node_id}",
        f"SECURITY_SERVER_URL={server_url}",
    ]
    CONFIG_PATH.write_text("\n".join(config_lines) + "\n", encoding="utf-8")
    CONFIG_PATH.chmod(0o600)

    # Populate the running environment so we can proceed without re-reading the file.
    os.environ["SECURITY_API_TOKEN"] = token
    os.environ["SECURITY_HMAC_SECRET"] = secret
    os.environ["SECURITY_NODE_ID"] = node_id
    os.environ["SECURITY_SERVER_URL"] = server_url

    sep = "=" * 62
    print(sep)
    print(" AUM CLIENT — FIRST RUN SETUP")
    print(sep)
    print(f" Config saved to: {CONFIG_PATH}")
    print()
    print(" Add this node to the server by appending the token below")
    print(" to SECURITY_API_TOKENS (comma-separated) and sharing the")
    print(" same SECURITY_HMAC_SECRET with the server environment.")
    print()
    print(f"   Node ID    : {node_id}")
    print(f"   API Token  : {token}")
    print(f"   HMAC Secret: {secret}")
    print(f"   Server URL : {server_url}")
    print()
    print(" The HMAC secret must match the SECURITY_HMAC_SECRET on the server.")
    print(" Edit", CONFIG_PATH, "to change the server URL before the next run.")
    print(sep)
    print()

    return True


def run_command(command: str, timeout: int = 25) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            shlex.split(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {command}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {command}"


def parse_updates(output: str) -> List[Dict[str, str]]:
    updates: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "->":
            updates.append(
                {
                    "name": parts[0],
                    "old_version": parts[1],
                    "new_version": parts[3],
                    "is_security": False,
                }
            )
        elif parts:
            updates.append(
                {
                    "name": parts[0],
                    "old_version": "?",
                    "new_version": "?",
                    "is_security": False,
                }
            )
    return updates


def parse_vulnerable_packages(output: str) -> Set[str]:
    vulnerable: Set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        vulnerable.add(line.split()[0].rstrip(":,"))
    return vulnerable


def collect_status() -> Dict[str, object]:
    update_code, update_stdout, update_stderr = run_command("checkupdates")
    warning = ""

    if update_code != 0:
        fallback_code, fallback_stdout, fallback_stderr = run_command("pacman -Qu")
        if fallback_code in (0, 1) and not fallback_stderr:
            update_stdout = fallback_stdout
            if update_stderr and "fakeroot" in update_stderr.lower():
                warning = (
                    "checkupdates needs fakeroot. Install with: "
                    "sudo pacman -S --needed base-devel"
                )
        elif update_stderr:
            warning = update_stderr

    updates = parse_updates(update_stdout)

    audit_code, audit_stdout, audit_stderr = run_command("arch-audit")
    vulnerable = parse_vulnerable_packages(audit_stdout) if audit_code == 0 else set()
    if audit_code != 0 and audit_stderr:
        warning = f"{warning} | {audit_stderr}".strip(" |")

    for update in updates:
        if update["name"] in vulnerable:
            update["is_security"] = True

    security_count = sum(1 for item in updates if item["is_security"])

    return {
        "node_id": os.getenv("SECURITY_NODE_ID", socket.gethostname()),
        "hostname": socket.gethostname(),
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "all_updates": len(updates),
        "security_updates": security_count,
        "updates": updates,
        "warning": warning,
    }


def post_status(payload: Dict[str, object]) -> None:
    server_url = os.getenv("SECURITY_SERVER_URL", "http://127.0.0.1:55000/api/node-report")
    token = os.getenv("SECURITY_API_TOKEN", "").strip()
    secret = os.getenv("SECURITY_HMAC_SECRET", "").strip()

    if not token:
        raise RuntimeError("SECURITY_API_TOKEN is required")
    if not secret:
        raise RuntimeError("SECURITY_HMAC_SECRET is required")

    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = str(int(time.time()))
    signature_base = f"{timestamp}.".encode("utf-8") + body
    signature = hmac.new(secret.encode("utf-8"), signature_base, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        server_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            print(f"Report sent. Server response: HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Server rejected report: HTTP {exc.code} {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach server: {exc}") from exc


def run_loop(interval: int) -> None:
    print(f"Reporting to server every {interval}s. Press Ctrl+C to stop.")
    while True:
        start = time.monotonic()
        try:
            status = collect_status()
            post_status(status)
        except Exception as exc:
            print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC] Error: {exc}", file=sys.stderr)
        elapsed = time.monotonic() - start
        sleep_for = max(0.0, interval - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    first_run = first_run_init()
    if first_run:
        answer = input("Server URL and node ID set. Send first report now? [y/N] ").strip().lower()
        if answer != "y":
            print("Skipping report. Run the script again when the token is added to the server.")
            sys.exit(0)

    try:
        interval = max(10, int(os.getenv("SECURITY_REPORT_INTERVAL", "60")))
    except ValueError:
        interval = 60

    run_loop(interval)
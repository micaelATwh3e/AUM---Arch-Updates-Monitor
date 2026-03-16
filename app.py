#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import shlex
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

DB_PATH = os.getenv("SECURITY_STATUS_DB", os.path.join("data", "node_status.db"))


@dataclass
class PackageUpdate:
    name: str
    old_version: str
    new_version: str
    raw_line: str
    is_security: bool = False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_utc_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def get_local_node_id() -> str:
    return os.getenv("SECURITY_LOCAL_NODE_ID", socket.gethostname())


def get_allowed_skew_seconds() -> int:
    raw = os.getenv("SECURITY_ALLOWED_SKEW_SECONDS", "300")
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_reports (
                node_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                checked_at TEXT NOT NULL,
                all_updates INTEGER NOT NULL,
                security_updates INTEGER NOT NULL,
                warning TEXT,
                status_json TEXT NOT NULL,
                api_timestamp INTEGER NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                hmac_secret TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_token(token: str, hmac_secret: str, label: str = "") -> None:
    """Persist a client token+secret pair. Safe to call while the server is running."""
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO tokens (token_hash, hmac_secret, label, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(token_hash) DO UPDATE SET
                hmac_secret = excluded.hmac_secret,
                label = excluded.label
            """,
            (_token_hash(token), hmac_secret, label, utc_now_iso()),
        )
        conn.commit()


def lookup_token_secret(token: str) -> Optional[str]:
    """Return the HMAC secret for a registered token, or None if not found."""
    with db_connect() as conn:
        row = conn.execute(
            "SELECT hmac_secret FROM tokens WHERE token_hash = ?",
            (_token_hash(token),),
        ).fetchone()
    return row["hmac_secret"] if row else None


def list_tokens() -> List[Dict[str, str]]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT label, created_at FROM tokens ORDER BY created_at"
        ).fetchall()
    return [{"label": r["label"] or "(unlabelled)", "created_at": r["created_at"]} for r in rows]


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


def parse_checkupdates(output: str) -> List[PackageUpdate]:
    updates: List[PackageUpdate] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Expected format: "pkgname old_version -> new_version"
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "->":
            updates.append(
                PackageUpdate(
                    name=parts[0],
                    old_version=parts[1],
                    new_version=parts[3],
                    raw_line=line,
                )
            )
        else:
            # Keep unknown format visible in UI.
            updates.append(
                PackageUpdate(
                    name=parts[0] if parts else line,
                    old_version="?",
                    new_version="?",
                    raw_line=line,
                )
            )

    return updates


def parse_arch_audit_packages(output: str) -> Set[str]:
    vulnerable_packages: Set[str] = set()

    for line in output.splitlines():
        clean = line.strip()
        if not clean:
            continue

        # arch-audit output starts with package name in typical text output.
        first = clean.split()[0]
        vulnerable_packages.add(first.rstrip(":,"))

    return vulnerable_packages


def collect_local_status() -> Dict[str, Any]:
    updates, update_error = get_arch_updates()
    vulnerable_packages, security_error = get_vulnerable_packages()

    for update in updates:
        if update.name in vulnerable_packages:
            update.is_security = True

    security_updates = [pkg for pkg in updates if pkg.is_security]
    warning = " | ".join([part for part in [update_error, security_error] if part])

    return {
        "node_id": get_local_node_id(),
        "hostname": socket.gethostname(),
        "checked_at": utc_now_iso(),
        "all_updates": len(updates),
        "security_updates": len(security_updates),
        "updates": [
            {
                "name": pkg.name,
                "old_version": pkg.old_version,
                "new_version": pkg.new_version,
                "is_security": pkg.is_security,
            }
            for pkg in updates
        ],
        "warning": warning,
    }


def validate_token_and_signature(raw_body: bytes) -> Tuple[bool, str]:
    provided_auth = request.headers.get("Authorization", "")
    if not provided_auth.startswith("Bearer "):
        return False, "Missing bearer token"

    provided_token = provided_auth.split(" ", 1)[1].strip()

    # Prefer per-token secret from DB; fall back to global env var for backward compat.
    secret = lookup_token_secret(provided_token)
    if secret is None:
        # Env-var fallback: check token list + global secret.
        env_tokens_raw = os.getenv("SECURITY_API_TOKENS", "")
        env_single = os.getenv("SECURITY_API_TOKEN", "").strip()
        env_tokens = {t.strip() for t in env_tokens_raw.split(",") if t.strip()}
        if env_single:
            env_tokens.add(env_single)
        if not env_tokens:
            return False, "Token not registered. Run: python app.py add-token --token <tok> --secret <sec> --label <name>"
        if provided_token not in env_tokens:
            return False, "Invalid bearer token"
        secret = os.getenv("SECURITY_HMAC_SECRET", "")
        if not secret:
            return False, "Server HMAC secret is not configured"

    timestamp_header = request.headers.get("X-Timestamp", "").strip()
    try:
        request_ts = int(timestamp_header)
    except ValueError:
        return False, "Invalid X-Timestamp header"

    if abs(int(time.time()) - request_ts) > get_allowed_skew_seconds():
        return False, "Timestamp outside allowed window"

    provided_sig = request.headers.get("X-Signature", "").strip().lower()
    if not provided_sig:
        return False, "Missing X-Signature header"

    signed_data = f"{request_ts}.".encode("utf-8") + raw_body
    expected_sig = hmac.new(secret.encode("utf-8"), signed_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        return False, "Invalid signature"

    return True, ""


def normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    node_id = str(payload.get("node_id", "")).strip()[:64]
    hostname = str(payload.get("hostname", "")).strip()[:128]
    checked_at = str(payload.get("checked_at", "")).strip()[:64]
    warning = str(payload.get("warning", "")).strip()[:800]
    all_updates = int(payload.get("all_updates", 0))
    security_updates = int(payload.get("security_updates", 0))
    updates_raw = payload.get("updates", [])

    if not node_id or not hostname or not checked_at:
        raise ValueError("node_id, hostname, and checked_at are required")

    if all_updates < 0 or security_updates < 0:
        raise ValueError("Update counts must be non-negative")

    if not isinstance(updates_raw, list):
        raise ValueError("updates must be a list")

    updates: List[Dict[str, Any]] = []
    for item in updates_raw[:300]:
        if not isinstance(item, dict):
            continue
        updates.append(
            {
                "name": str(item.get("name", "")).strip()[:120],
                "old_version": str(item.get("old_version", "")).strip()[:120],
                "new_version": str(item.get("new_version", "")).strip()[:120],
                "is_security": bool(item.get("is_security", False)),
            }
        )

    return {
        "node_id": node_id,
        "hostname": hostname,
        "checked_at": checked_at,
        "warning": warning,
        "all_updates": all_updates,
        "security_updates": security_updates,
        "updates": updates,
    }


def upsert_node_report(report: Dict[str, Any], ip_address: str, api_timestamp: int) -> Tuple[bool, str]:
    last_seen = utc_now_iso()
    status_json = json.dumps(report, separators=(",", ":"), sort_keys=True)

    with db_connect() as conn:
        row = conn.execute(
            "SELECT api_timestamp FROM node_reports WHERE node_id = ?",
            (report["node_id"],),
        ).fetchone()

        if row and api_timestamp <= int(row["api_timestamp"]):
            return False, "Rejected replayed or out-of-order report"

        conn.execute(
            """
            INSERT INTO node_reports (
                node_id,
                hostname,
                ip_address,
                checked_at,
                all_updates,
                security_updates,
                warning,
                status_json,
                api_timestamp,
                last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                hostname = excluded.hostname,
                ip_address = excluded.ip_address,
                checked_at = excluded.checked_at,
                all_updates = excluded.all_updates,
                security_updates = excluded.security_updates,
                warning = excluded.warning,
                status_json = excluded.status_json,
                api_timestamp = excluded.api_timestamp,
                last_seen = excluded.last_seen
            """,
            (
                report["node_id"],
                report["hostname"],
                ip_address,
                report["checked_at"],
                report["all_updates"],
                report["security_updates"],
                report["warning"],
                status_json,
                api_timestamp,
                last_seen,
            ),
        )
        conn.commit()

    return True, ""


def load_remote_reports(local_node_id: str) -> List[Dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT node_id, hostname, ip_address, checked_at, all_updates, security_updates,
                   warning, status_json, last_seen
            FROM node_reports
            WHERE node_id != ?
            ORDER BY security_updates DESC, all_updates DESC, last_seen DESC
            """,
            (local_node_id,),
        ).fetchall()

    reports: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for row in rows:
        last_seen_raw = row["last_seen"]
        last_seen_dt = parse_utc_ts(last_seen_raw)
        stale = True
        if last_seen_dt:
            stale = (now - last_seen_dt).total_seconds() > 1800

        status_payload: Dict[str, Any] = {}
        try:
            status_payload = json.loads(row["status_json"])
        except json.JSONDecodeError:
            status_payload = {}

        reports.append(
            {
                "node_id": row["node_id"],
                "hostname": row["hostname"],
                "ip_address": row["ip_address"],
                "checked_at": row["checked_at"],
                "all_updates": row["all_updates"],
                "security_updates": row["security_updates"],
                "warning": row["warning"] or "",
                "last_seen": last_seen_raw,
                "stale": stale,
                "updates": status_payload.get("updates", []),
            }
        )

    return reports


init_db()


def get_arch_updates() -> Tuple[List[PackageUpdate], str]:
    code, stdout, stderr = run_command("checkupdates")

    if code == 0:
        return parse_checkupdates(stdout), ""

    # checkupdates depends on fakeroot (from base-devel); fallback keeps UI useful.
    fallback_code, fallback_stdout, fallback_stderr = run_command("pacman -Qu")
    # pacman -Qu may return 1 when there are no updates on some setups.
    if fallback_code in (0, 1) and not fallback_stderr:
        warning = ""
        if "fakeroot" in stderr.lower():
            warning = (
                "checkupdates needs fakeroot. Install it with: "
                "sudo pacman -S --needed base-devel"
            )
        elif stderr and fallback_stdout:
            warning = f"checkupdates failed; using pacman -Qu fallback. Details: {stderr}"
        elif stderr and not fallback_stdout:
            # No updates is a normal state; do not show a warning banner for it.
            warning = ""
        elif fallback_stdout:
            warning = "checkupdates failed; using pacman -Qu fallback."

        return parse_checkupdates(fallback_stdout), warning

    if stdout:
        # Some tools may still print helpful info even with non-zero exit.
        return parse_checkupdates(stdout), stderr

    if "fakeroot" in stderr.lower():
        return (
            [],
            "Cannot find fakeroot binary. Install with: sudo pacman -S --needed base-devel",
        )

    parts = []
    if stderr:
        parts.append(f"checkupdates: {stderr}")
    if fallback_stderr:
        parts.append(f"pacman -Qu: {fallback_stderr}")

    if parts:
        return [], " | ".join(parts)

    return [], "Unable to fetch updates. checkupdates and pacman -Qu returned no usable output."


def get_vulnerable_packages() -> Tuple[Set[str], str]:
    code, stdout, stderr = run_command("arch-audit")

    if code == 0 and stdout:
        return parse_arch_audit_packages(stdout), ""

    if code == 0 and not stdout:
        return set(), ""

    return set(), stderr or "Unable to fetch security advisories."


@app.post("/api/node-report")
def api_node_report():
    raw_body = request.get_data(cache=False)
    if not raw_body:
        return jsonify({"ok": False, "error": "Empty body"}), 400

    if len(raw_body) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"ok": False, "error": "Payload too large"}), 413

    valid, reason = validate_token_and_signature(raw_body)
    if not valid:
        return jsonify({"ok": False, "error": reason}), 401

    timestamp_header = request.headers.get("X-Timestamp", "0").strip()
    api_timestamp = int(timestamp_header)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"ok": False, "error": "Body must be valid JSON"}), 400

    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "JSON body must be an object"}), 400

    try:
        report = normalize_payload(payload)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip_address = ip_address.split(",", 1)[0].strip()

    stored, store_error = upsert_node_report(report, ip_address, api_timestamp)
    if not stored:
        return jsonify({"ok": False, "error": store_error}), 409

    return jsonify({"ok": True}), 200


@app.route("/")
def index():
    local_status = collect_local_status()

    remote_reports = load_remote_reports(local_status["node_id"])
    node_reports = [
        {
            "node_id": local_status["node_id"],
            "hostname": local_status["hostname"],
            "ip_address": "127.0.0.1",
            "checked_at": local_status["checked_at"],
            "all_updates": local_status["all_updates"],
            "security_updates": local_status["security_updates"],
            "warning": local_status["warning"],
            "last_seen": local_status["checked_at"],
            "stale": False,
            "is_local": True,
            "updates": local_status["updates"],
        }
    ]

    for report in remote_reports:
        report["is_local"] = False
        node_reports.append(report)

    nodes_with_security = sum(1 for node in node_reports if int(node["security_updates"]) > 0)
    stale_nodes = sum(1 for node in node_reports if node["stale"])

    return render_template(
        "index.html",
        checked_at=local_status["checked_at"],
        node_reports=node_reports,
        node_count=len(node_reports),
        nodes_with_security=nodes_with_security,
        stale_nodes=stale_nodes,
    )


def _cli_add_token(args: List[str]) -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog="app.py add-token",
        description="Register a client token so it can report to this server.",
    )
    parser.add_argument("--token", required=True, help="Bearer token from the client first-run output")
    parser.add_argument("--secret", required=True, help="HMAC secret from the client first-run output")
    parser.add_argument("--label", default="", help="Human-readable name (e.g. node hostname)")
    parsed = parser.parse_args(args)
    init_db()
    register_token(parsed.token, parsed.secret, parsed.label)
    print(f"Token registered for '{parsed.label or '(no label)'}'. The client can now report.")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "add-token":
        _cli_add_token(sys.argv[2:])
        sys.exit(0)
    init_db()
    app.run(host="0.0.0.0", port=55000, debug=True)
# AUM — Arch Updates Monitor

A Flask dashboard that aggregates Arch Linux package update status from multiple machines in one place. Security-related packages are highlighted in red so they are never missed.

- **Server**: Flask web dashboard and secure report ingestion API
- **Clients**: each Arch machine runs `client.py` and reports its update status every minute
- **Dashboard**: shows all nodes in one table; clicking a node's security badge expands the affected packages
- Security tagging uses `arch-audit` output cross-referenced against pending updates from `checkupdates`

## Requirements

- Arch Linux (server and clients)
- Python 3.10+
- `pacman-contrib` (provides `checkupdates`)
- `arch-audit` (CVE/advisory detection)

```bash
sudo pacman -Syu pacman-contrib arch-audit
```

## Server Setup

```bash
git clone https://github.com/micaelATwh3e/AUM---Arch-Updates-Monitor.git
cd AUM---Arch-Updates-Monitor
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:55000`.

### Optional environment variables

| Variable | Default | Description |
|---|---|---|
| `SECURITY_LOCAL_NODE_ID` | hostname | Identity shown for the server node |
| `SECURITY_STATUS_DB` | `data/node_status.db` | Path to the SQLite database |
| `SECURITY_ALLOWED_SKEW_SECONDS` | `300` | Max clock drift allowed for client reports |

### Security model

Client reports are authenticated with two independent controls:

- **Bearer token** — unique per client, stored as a SHA-256 hash in the DB
- **HMAC-SHA256 signature** — signs `timestamp + body`; unique secret per client
- **Timestamp window** — replays and out-of-order reports are rejected

Recommended hardening: run behind an HTTPS reverse proxy (nginx, Caddy) and restrict access to trusted networks or a VPN.

## Adding a Client Node

**1. On the client machine — first run:**

```bash
python client.py
```

The script generates a unique token and HMAC secret, saves them to `~/.config/aum-client.env` (mode `600`), and prints them:

```
==============================================================
 AUM CLIENT — FIRST RUN SETUP
==============================================================
   Node ID    : laptop-arch
   API Token  : 4a9f...
   HMAC Secret: d8c1...
   Server URL : http://127.0.0.1:55000/api/node-report
==============================================================
```

Edit `~/.config/aum-client.env` to set the correct `SECURITY_SERVER_URL` before continuing.

**2. On the server — register the token (no restart needed):**

```bash
python app.py add-token --token <token> --secret <hmac-secret> --label laptop-arch
```

**3. The client will then report every 60 seconds automatically.**

### Client environment variables

| Variable | Default | Description |
|---|---|---|
| `SECURITY_SERVER_URL` | `http://127.0.0.1:55000/api/node-report` | Server endpoint |
| `SECURITY_API_TOKEN` | *(generated)* | Bearer token |
| `SECURITY_HMAC_SECRET` | *(generated)* | HMAC signing secret |
| `SECURITY_NODE_ID` | hostname | Node label shown in dashboard |
| `SECURITY_REPORT_INTERVAL` | `60` | Seconds between reports (minimum 10) |
| `SECURITY_CLIENT_CONFIG` | `~/.config/aum-client.env` | Config file path |

### Running the client as a systemd service

```ini
# ~/.config/systemd/user/aum-client.service
[Unit]
Description=AUM security update reporter

[Service]
ExecStart=/path/to/.venv/bin/python /path/to/client.py
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now aum-client
```

## Notes

- `checkupdates` requires `fakeroot` (from `base-devel`). If missing, the client falls back to `pacman -Qu` automatically.
- The app and client only read package info — they do not install or modify anything.
- The token database (`data/`) and client config (`~/.config/aum-client.env`) are excluded from git via `.gitignore`.

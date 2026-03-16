# Arch Security Updates Monitor

This project now supports a secure server-client model:

- Server: Flask dashboard and secure ingestion API
- Clients: report their local update status to the server
- Dashboard: shows local + remote node status on one page

Security tagging is based on `arch-audit` output and matched against packages from `checkupdates`.

## Requirements

- Arch Linux
- Python 3.10+
- `pacman-contrib` (for `checkupdates`)
- `arch-audit` (for vulnerability/security package detection)

Install required system tools:

```bash
sudo pacman -Syu pacman-contrib arch-audit
```

## Setup

```bash
cd /home/iwery/security
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Server Configuration (Secure)

Set these environment variables on the server:

```bash
export SECURITY_API_TOKENS="token-node-a,token-node-b"
export SECURITY_HMAC_SECRET="replace-with-long-random-secret"
export SECURITY_ALLOWED_SKEW_SECONDS=300
export SECURITY_LOCAL_NODE_ID="main-server"
export SECURITY_STATUS_DB="data/node_status.db"
```

Security model for client reports:

- bearer token authentication (`Authorization: Bearer ...`)
- HMAC-SHA256 request signatures (`X-Signature`)
- signed timestamp validation (`X-Timestamp`)
- replay protection (older/out-of-order signed reports are rejected)

Recommended hardening:

- run behind HTTPS reverse proxy (nginx/caddy)
- restrict inbound access to trusted networks/VPN
- rotate API tokens and HMAC secret periodically

## Run

```bash
python app.py
```

Open:

```text
http://127.0.0.1:55000
```

## Client Reporting

On each client installation, set:

```bash
export SECURITY_SERVER_URL="https://your-server.example.com/api/node-report"
export SECURITY_API_TOKEN="token-node-a"
export SECURITY_HMAC_SECRET="same-secret-as-server"
export SECURITY_NODE_ID="laptop-arch"
```

Send one report:

```bash
python client.py
```

Suggested schedule (every 10 minutes):

```bash
*/10 * * * * cd /home/iwery/security && /home/iwery/security/.venv/bin/python client.py
```

## Notes

- If `checkupdates` or `arch-audit` is missing, the page will show a warning.
- The app only reads update/advisory info; it does not install updates.
- If `checkupdates` fails due to missing `fakeroot`, it automatically falls back to `pacman -Qu`.
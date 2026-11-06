# Home Network Monitor

A read-only starter monitor for a Linux host. It polls the host's Linux neighbor cache, records first-seen MAC addresses in SQLite, presents a local dashboard, and can send optional email alerts.

## Run

Requires Python 3.10+ and the Linux `ip` command (`iproute2`). No Python packages are needed.

```sh
cd home-network-monitor
python3 netwatch.py
```

Open <http://127.0.0.1:8765>. Stop with Ctrl+C. The default database is `netwatch.sqlite3` in the current directory. Override it with `NETWATCH_DB=/path/to/netwatch.sqlite3`.

The dashboard binds only to localhost. Do not expose it directly to the internet. This version intentionally has no router write access and does not change VPN or proxy settings.

## Email alerts

Set these environment variables before starting the monitor:

```sh
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="465"
export SMTP_USER="your-account"
export SMTP_PASSWORD="your-app-password"
export ALERT_EMAIL_FROM="monitor@example.com"
export ALERT_EMAIL_TO="you@example.com"
python3 netwatch.py
```

Port 465 uses implicit TLS; other ports use STARTTLS. Keep credentials out of source control and shell history. Email settings are optional; events are still stored locally.

To label known MAC addresses in the dashboard, set `NETWATCH_ALLOWLIST` to comma-separated MAC addresses. A first-seen device still creates an event and an alert, even when allowlisted.

## Scope and limitations

- The monitor observes entries already present in this Linux host's neighbor cache. It does not actively scan or probe the LAN, and a quiet or isolated device may not appear.
- MAC addresses are not reliable identities; devices may randomize them, and a MAC address can be spoofed.
- This is not an intrusion detection system. It cannot determine that traffic is malicious or inspect communications from other apps.
- Route and proxy indicators describe this host only. Tunnel interface names are a heuristic, not proof that a VPN is working. It cannot manage the router or other devices.
- Whole-network device inventory, VPN routing, and proxy enforcement require a supported router/firewall integration and its authenticated administrative API. The router model is needed before adding that integration.

## Test

```sh
python3 -m unittest -v
```
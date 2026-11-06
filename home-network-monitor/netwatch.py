#!/usr/bin/env python3
"""Read-only local network device monitor for Linux."""

from __future__ import annotations

import argparse
import email.message
import json
import os
import re
import smtplib
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DB_PATH = Path(os.environ.get("NETWATCH_DB", "netwatch.sqlite3"))
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
TUNNEL_NAMES = ("wg", "tun", "tap", "tailscale", "zt")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_neighbor_output(output: str) -> list[dict[str, str]]:
    """Parse `ip neigh` output; only entries with a hardware address count."""
    devices = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or "dev" not in parts or "lladdr" not in parts:
            continue
        try:
            device = {
                "ip": parts[0],
                "interface": parts[parts.index("dev") + 1],
                "mac": parts[parts.index("lladdr") + 1].lower(),
                "state": parts[-1].upper(),
            }
        except (IndexError, ValueError):
            continue
        if MAC_PATTERN.fullmatch(device["mac"]):
            devices.append(device)
    return devices


def run_ip(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["ip", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            interface TEXT NOT NULL,
            state TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            known INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT NOT NULL
        );
        """
    )
    return connection


def allowed_macs() -> set[str]:
    return {
        item.strip().lower()
        for item in os.environ.get("NETWATCH_ALLOWLIST", "").split(",")
        if MAC_PATTERN.fullmatch(item.strip())
    }


def send_email(subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST")
    sender = os.environ.get("ALERT_EMAIL_FROM")
    recipient = os.environ.get("ALERT_EMAIL_TO")
    if not all((host, sender, recipient)):
        return

    message = email.message.EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    port = int(os.environ.get("SMTP_PORT", "465"))
    username = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as client:
            if username and password:
                client.login(username, password)
            client.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=10) as client:
            client.starttls()
            if username and password:
                client.login(username, password)
            client.send_message(message)


def record_scan(devices: list[dict[str, str]]) -> None:
    known_macs = allowed_macs()
    alerts: list[str] = []
    timestamp = now_utc()
    with connect_db() as connection:
        for device in devices:
            mac = device["mac"]
            known = int(mac in known_macs)
            existing = connection.execute(
                "SELECT mac FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
            if existing is None:
                label = "known" if known else "unrecognized"
                message = (
                    f"New {label} device: {device['ip']} ({mac}) "
                    f"on {device['interface']}"
                )
                connection.execute(
                    "INSERT INTO events(timestamp, kind, message) VALUES (?, ?, ?)",
                    (timestamp, "new-device", message),
                )
                alerts.append(message)
            connection.execute(
                """INSERT INTO devices(mac, ip, interface, state, first_seen,
                   last_seen, known) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,
                   interface=excluded.interface, state=excluded.state,
                   last_seen=excluded.last_seen, known=excluded.known""",
                (
                    mac,
                    device["ip"],
                    device["interface"],
                    device["state"],
                    timestamp,
                    timestamp,
                    known,
                ),
            )

    for message in alerts:
        try:
            send_email("Network monitor: new device", message)
        except (OSError, smtplib.SMTPException, ValueError) as error:
            with connect_db() as connection:
                connection.execute(
                    "INSERT INTO events(timestamp, kind, message) VALUES (?, ?, ?)",
                    (now_utc(), "email-error", f"Email alert failed: {error}"),
                )


def current_status() -> dict[str, Any]:
    route = run_ip(["route", "show", "default"]).strip()
    interface = ""
    route_parts = route.split()
    if "dev" in route_parts:
        try:
            interface = route_parts[route_parts.index("dev") + 1]
        except IndexError:
            pass
    likely_tunnel = interface.lower().startswith(TUNNEL_NAMES)
    proxy_enabled = any(
        os.environ.get(name)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    )
    with connect_db() as connection:
        device_count = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    return {
        "default_route": route or "Unavailable",
        "interface": interface or "Unknown",
        "likely_tunnel_interface": likely_tunnel,
        "host_proxy_environment_set": bool(proxy_enabled),
        "observed_devices": device_count,
        "checked_at": now_utc(),
        "note": "VPN and proxy status is advisory and describes this host only.",
    }


def recent_data() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with connect_db() as connection:
        devices = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM devices ORDER BY known ASC, last_seen DESC"
            )
        ]
        events = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT 100"
            )
        ]
    return devices, events


def monitor_loop(interval: int) -> None:
    while True:
        record_scan(parse_neighbor_output(run_ip(["neigh", "show"])))
        time.sleep(interval)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home Network Monitor</title>
<style>
:root{color-scheme:light;--ink:#172622;--muted:#60716c;--paper:#f3f5ef;--line:#d5ddd5;--green:#146b52;--red:#a64032}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
header{background:#173c32;color:#f5f4e9;padding:24px max(20px,calc((100vw - 1100px)/2))}
h1{font-size:24px;margin:0}header p{margin:4px 0 0;color:#d4e4d8}
main{max-width:1100px;margin:24px auto;padding:0 20px}.summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:24px}
.metric{background:#fff;padding:16px}.metric b{display:block;font-size:19px}.metric span{color:var(--muted);font-size:13px}
section{margin:24px 0}h2{font-size:17px;margin:0 0 10px}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}td{overflow-wrap:anywhere}.note{font-size:13px;color:var(--muted)}
@media(max-width:650px){.summary{grid-template-columns:1fr}table{font-size:13px}th,td{padding:8px 6px}.hide-mobile{display:none}}
</style></head><body><header><h1>Home Network Monitor</h1><p>Local device visibility and network events</p></header>
<main><div class="summary" id="summary"></div><section><h2>Observed devices</h2><table><thead><tr><th>IP</th><th>MAC</th><th>Interface</th><th>State</th><th>Known</th><th class="hide-mobile">Last seen</th></tr></thead><tbody id="devices"></tbody></table></section>
<section><h2>Recent events</h2><table><thead><tr><th>Time</th><th>Type</th><th>Event</th></tr></thead><tbody id="events"></tbody></table></section>
<p class="note">This reads the Linux neighbor cache only. It does not inspect message contents or reliably discover every device. VPN and proxy indicators are advisory for this host, not network-wide controls.</p></main>
<script>
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function refresh(){const r=await fetch('/api/data');const d=await r.json();const s=d.status;
document.querySelector('#summary').innerHTML=`<div class="metric"><b>${esc(s.observed_devices)}</b><span>observed devices</span></div><div class="metric"><b>${esc(s.interface)}</b><span>default-route interface${s.likely_tunnel_interface?' · likely tunnel name':''}</span></div><div class="metric"><b>${s.host_proxy_environment_set?'Configured':'Not detected'}</b><span>proxy variables on monitor host</span></div>`;
document.querySelector('#devices').innerHTML=d.devices.map(x=>`<tr><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.interface)}</td><td>${esc(x.state)}</td><td>${x.known?'Yes':'No'}</td><td class="hide-mobile">${esc(x.last_seen)}</td></tr>`).join('')||'<tr><td colspan="6">No devices observed yet.</td></tr>';
document.querySelector('#events').innerHTML=d.events.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.kind)}</td><td>${esc(x.message)}</td></tr>`).join('')||'<tr><td colspan="3">No events yet.</td></tr>'}
refresh();setInterval(refresh,10000);
</script></body></html>"""


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/data":
            devices, events = recent_data()
            body = json.dumps(
                {"status": current_status(), "devices": devices, "events": events}
            ).encode()
            content_type = "application/json; charset=utf-8"
        elif self.path == "/":
            body = PAGE.encode()
            content_type = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=int, default=30, help="poll interval in seconds")
    parser.add_argument("--host", default="127.0.0.1", help="dashboard bind address")
    parser.add_argument("--port", type=int, default=8765, help="dashboard port")
    args = parser.parse_args()
    if args.interval < 5:
        parser.error("--interval must be at least 5 seconds")
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        parser.error("dashboard must bind to localhost in this version")

    connect_db().close()
    threading.Thread(target=monitor_loop, args=(args.interval,), daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), RequestHandler)
    print(f"Dashboard: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
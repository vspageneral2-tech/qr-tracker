import os
import json
import socket
import sqlite3
from datetime import datetime

import qrcode
import requests
from flask import Flask, render_template, request, redirect, url_for, abort
from ipaddress import ip_address
from user_agents import parse as parse_ua
from zoneinfo import ZoneInfo  # Python 3.9+

# -------------------
# Config
# -------------------
app = Flask(__name__)
os.makedirs("static/qrs", exist_ok=True)

DB_PATH = os.getenv("DB_PATH", "db.sqlite")
PORT = int(os.getenv("PORT", "5000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g., https://yourdomain.com

# -------------------
# Database
# -------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()

        # scans (each time someone opens /scan/<scan_id>)
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            qr_label TEXT,
            timestamp TEXT,
            ip TEXT,
            user_agent TEXT,
            device_family TEXT,
            os_family TEXT,
            browser_family TEXT,
            city TEXT,
            region TEXT,
            country TEXT,
            lat REAL,
            lon REAL
        )''')

        # clicks (which link they chose)
        c.execute('''CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            link TEXT,
            timestamp TEXT
        )''')

        # one row per QR you generate (its label, links, png path)
        c.execute('''CREATE TABLE IF NOT EXISTS qr_configs (
            scan_id TEXT PRIMARY KEY,
            qr_label TEXT,
            links_json TEXT,          -- JSON: [{"text":"..","target":".."},...]
            qr_image_path TEXT,       -- e.g., static/qrs/169....png
            created_at TEXT
        )''')

        # Add missing columns defensively (for older DBs)
        for col, typ in [
            ("qr_label", "TEXT"),
            ("device_family", "TEXT"),
            ("os_family", "TEXT"),
            ("browser_family", "TEXT"),
            ("city", "TEXT"),
            ("region", "TEXT"),
            ("country", "TEXT"),
            ("lat", "REAL"),
            ("lon", "REAL"),
        ]:
            try:
                c.execute(f"ALTER TABLE scans ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError:
                pass

        conn.commit()

init_db()

# -------------------
# Helpers
# -------------------
def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def is_private_or_invalid_ip(ip):
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except Exception:
        return True

def geolocate_ip(ip):
    if not ip or is_private_or_invalid_ip(ip):
        return {"city": None, "region": None, "country": None, "lat": None, "lon": None}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        j = r.json()
        if j.get("status") == "success":
            return {
                "city": j.get("city"),
                "region": j.get("regionName"),
                "country": j.get("country"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
            }
    except Exception:
        pass
    return {"city": None, "region": None, "country": None, "lat": None, "lon": None}

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def external_base_url():
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    ip = get_lan_ip()
    return f"http://{ip}:{PORT}"

def time_ist(iso_ts: str) -> str:
    """Render ISO timestamp in IST nicely."""
    try:
        dt = datetime.fromisoformat(iso_ts)
        return dt.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return iso_ts

# -------------------
# Routes
# -------------------
@app.route("/")
def home():
    return render_template("home.html")

# List all saved QRs
@app.route("/qr-list")
def qr_list():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM qr_configs ORDER BY created_at DESC").fetchall()

    items = []
    for r in rows:
        d = dict(r)
        d["created_local"] = time_ist(d["created_at"])
        d["scan_url"] = f"{external_base_url()}{url_for('scan_page', scan_id=d['scan_id'])}?label={d.get('qr_label') or ''}"
        # Parse links JSON here so template doesn't need to
        try:
            d["links"] = json.loads(d.get("links_json") or "[]")
        except Exception:
            d["links"] = []
        items.append(d)

    return render_template("qr_list.html", items=items)

# Create a QR with label + up to 3 links
@app.route("/generate", methods=["GET", "POST"])
def generate_qr():
    if request.method == "GET":
        return render_template("generate.html", img_path=None, scan_url=None, label=None)

    label = (request.form.get("label") or "").strip()

    # Read 3 link label+URL pairs
    link_texts = [request.form.get(f"text{i}", "").strip() for i in (1, 2, 3)]
    link_urls  = [request.form.get(f"url{i}", "").strip()  for i in (1, 2, 3)]

    links = []
    for t, u in zip(link_texts, link_urls):
        if t and u:
            links.append({"text": t, "target": u})

    if len(links) == 0:
        return "Please provide at least one link label + URL.", 400

    # Make a unique scan_id and scan URL
    scan_id = str(int(datetime.now().timestamp()))
    scan_url = f"{external_base_url()}{url_for('scan_page', scan_id=scan_id)}?label={label}"

    # Create and save the QR image
    img = qrcode.make(scan_url)
    file_path = f"static/qrs/{scan_id}.png"
    img.save(file_path)

    # Save QR config so it appears in /qr-list and is used at scan time
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO qr_configs (scan_id, qr_label, links_json, qr_image_path, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, label, json.dumps(links), file_path, datetime.utcnow().isoformat())
        )
        conn.commit()

    return render_template("generate.html", img_path=f"/{file_path}", scan_url=scan_url, label=label)

# When someone scans the QR
@app.route("/scan/<scan_id>")
def scan_page(scan_id):
    # Look up saved links for this QR; 404 if not found
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cfg = conn.execute("SELECT * FROM qr_configs WHERE scan_id = ?", (scan_id,)).fetchone()
    if not cfg:
        abort(404)

    qr_label = request.args.get("label") or cfg["qr_label"]

    client_ip = get_client_ip()
    geo = geolocate_ip(client_ip)

    ua = parse_ua(request.user_agent.string or "")
    device_family = ua.device.family or None
    os_family = ua.os.family or None
    browser_family = ua.browser.family or None

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (scan_id, qr_label, timestamp, ip, user_agent, device_family, os_family, browser_family, city, region, country, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            qr_label,
            datetime.utcnow().isoformat(),
            client_ip,
            request.user_agent.string,
            device_family,
            os_family,
            browser_family,
            geo["city"], geo["region"], geo["country"], geo["lat"], geo["lon"]
        ))
        conn.commit()

    links_cfg = json.loads(cfg["links_json"]) if cfg["links_json"] else []
    # Send through /click so we log which one was chosen
    links = [{"text": l["text"], "url": url_for("click_link", scan_id=scan_id, link=l["target"])} for l in links_cfg]
    return render_template("scan.html", links=links)

# Log which link was clicked
@app.route("/click")
def click_link():
    scan_id = request.args.get("scan_id")
    link = request.args.get("link")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO clicks (scan_id, link, timestamp) VALUES (?, ?, ?)",
                  (scan_id, link, datetime.utcnow().isoformat()))
        conn.commit()
    return redirect(link or "/")

# Admin dashboard with readable time & named columns
@app.route("/admin")
def admin():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # Scans
        scans_rows = conn.execute("""
            SELECT id, scan_id, qr_label, timestamp, ip, user_agent,
                   device_family, os_family, browser_family,
                   city, region, country, lat, lon
            FROM scans
            ORDER BY timestamp DESC
        """).fetchall()

        # Clicks
        clicks_rows = conn.execute("""
            SELECT id, scan_id, link, timestamp
            FROM clicks
            ORDER BY timestamp DESC
        """).fetchall()

        # ✅ Saved QRs (this was missing in your version)
        qr_rows = conn.execute("""
            SELECT scan_id, qr_label, links_json, qr_image_path, created_at
            FROM qr_configs
            ORDER BY created_at DESC
        """).fetchall()

    # prettify times
    scans = []
    for r in scans_rows:
        d = dict(r)
        d["time_local"] = time_ist(r["timestamp"])
        scans.append(d)

    clicks = []
    for r in clicks_rows:
        d = dict(r)
        d["time_local"] = time_ist(r["timestamp"])
        clicks.append(d)

    # build Saved QRs list
    qr_items = []
    for r in qr_rows:   # ✅ now this works
        d = dict(r)
        d["created_local"] = time_ist(d["created_at"])
        try:
            d["links"] = json.loads(d.get("links_json") or "[]")
        except Exception:
            d["links"] = []
        d["scan_url"] = f"{external_base_url()}{url_for('scan_page', scan_id=d['scan_id'])}?label={d.get('qr_label') or ''}"
        qr_items.append(d)

    return render_template(
        "admin.html",
        scans=scans,
        clicks=clicks,
        qr_items=qr_items,          # <-- pass to template
        base_url=external_base_url()
    )

# -------------------
# Run (local dev)
# -------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)

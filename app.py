import os
import socket
import sqlite3
from datetime import datetime

import qrcode
import requests
from flask import Flask, render_template, request, redirect, url_for
from ipaddress import ip_address
from user_agents import parse as parse_ua  # NEW: for device info

# -------------------
# Config
# -------------------
app = Flask(__name__)
os.makedirs("static/qrs", exist_ok=True)

DB_PATH = os.getenv("DB_PATH", "db.sqlite")
PORT = int(os.getenv("PORT", "5000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. https://yourdomain.com

# Fixed list of 3 links (edit text + target URLs here)
LINKS = [
    {"text": "Link 1", "target": "https://example.com/a"},
    {"text": "Link 2", "target": "https://example.com/b"},
    {"text": "Link 3", "target": "https://example.com/c"},
]

# -------------------
# Database
# -------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
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

        c.execute('''CREATE TABLE IF NOT EXISTS clicks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        link TEXT,
                        timestamp TEXT
                    )''')

        # Add missing columns if DB already existed
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

# -------------------
# Routes
# -------------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/generate", methods=["GET", "POST"])
def generate_qr():
    if request.method == "GET":
        return render_template("generate.html", img_path=None, scan_url=None, label=None)

    label = (request.form.get("label") or "").strip()
    scan_id = str(int(datetime.now().timestamp()))
    scan_url = f"{external_base_url()}{url_for('scan_page', scan_id=scan_id)}?label={label}"

    # Make QR image
    img = qrcode.make(scan_url)
    file_path = f"static/qrs/{scan_id}.png"
    img.save(file_path)

    return render_template("generate.html", img_path=f"/{file_path}", scan_url=scan_url, label=label)

@app.route("/scan/<scan_id>")
def scan_page(scan_id):
    qr_label = request.args.get("label")

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
            datetime.now().isoformat(),
            client_ip,
            request.user_agent.string,
            device_family,
            os_family,
            browser_family,
            geo["city"], geo["region"], geo["country"], geo["lat"], geo["lon"]
        ))
        conn.commit()

    # Build the fixed 3 links
    links = [
        {"text": l["text"], "url": url_for("click_link", scan_id=scan_id, link=l["target"])}
        for l in LINKS
    ]
    return render_template("scan.html", links=links)

@app.route("/click")
def click_link():
    scan_id = request.args.get("scan_id")
    link = request.args.get("link")

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO clicks (scan_id, link, timestamp) VALUES (?, ?, ?)",
                  (scan_id, link, datetime.now().isoformat()))
        conn.commit()

    return redirect(link or "/")

@app.route("/admin")
def admin():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        scans = c.fetchall()
        c.execute("SELECT * FROM clicks ORDER BY timestamp DESC")
        clicks = c.fetchall()
    return render_template("admin.html", scans=scans, clicks=clicks, base_url=external_base_url())

# -------------------
# Run
# -------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)

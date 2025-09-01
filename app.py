import os
import socket
from datetime import datetime

import qrcode
import requests
import sqlite3
from flask import Flask, render_template, request, redirect, url_for

# -------------------
# Basic Flask setup
# -------------------
app = Flask(__name__)
os.makedirs("static/qrs", exist_ok=True)

# replace the DB_PATH line you have now with this:
DB_PATH = os.getenv("DB_PATH", "db.sqlite")

PORT = int(os.getenv("PORT", "5000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # optional: e.g. https://your-ngrok-url.ngrok-free.app

# -------------------
# Database
# -------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        timestamp TEXT,
                        ip TEXT,
                        user_agent TEXT,
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

        # If older DB exists without new columns, add them safely
        for col, typ in [("city", "TEXT"), ("region", "TEXT"), ("country", "TEXT"), ("lat", "REAL"), ("lon", "REAL")]:
            try:
                c.execute(f"ALTER TABLE scans ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError:
                pass

        conn.commit()

init_db()

# -------------------
# Helpers
# -------------------
from ipaddress import ip_address

def get_client_ip():
    """Try to get real client IP (works behind proxies if X-Forwarded-For is passed)."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # first IP in the list is the original client
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def is_private_or_invalid_ip(ip):
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except Exception:
        return True

def geolocate_ip(ip):
    """Free lookup via ip-api.com. Skip private/loopback IPs."""
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
    """Detect your machine's LAN IP (so phones on same Wi-Fi can reach it)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # We don't actually connect to 8.8.8.8, just use it to pick the right interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # fallback: hostname resolution
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def external_base_url():
    """Where should the QR point? Uses PUBLIC_BASE_URL if provided, else LAN IP."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    ip = get_lan_ip()
    return f"http://{ip}:{PORT}"

# -------------------
# Routes
# -------------------
@app.route("/")
def home():
    # Simple landing page that links to generate & admin
    return render_template("home.html")

@app.route("/generate")
def generate_qr():
    # Unique scan id based on timestamp
    scan_id = str(int(datetime.now().timestamp()))
    scan_url = f"{external_base_url()}{url_for('scan_page', scan_id=scan_id)}"

    # Make QR image
    img = qrcode.make(scan_url)
    file_path = f"static/qrs/{scan_id}.png"
    img.save(file_path)

    return render_template("generate.html", img_path=f"/{file_path}", scan_url=scan_url)

@app.route("/scan/<scan_id>")
def scan_page(scan_id):
    client_ip = get_client_ip()
    geo = geolocate_ip(client_ip)

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (scan_id, timestamp, ip, user_agent, city, region, country, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            datetime.now().isoformat(),
            client_ip,
            request.user_agent.string,
            geo["city"], geo["region"], geo["country"], geo["lat"], geo["lon"]
        ))
        conn.commit()

    # Edit this list to your real destinations
    links = [
        {"text": "Google",  "url": url_for("click_link", scan_id=scan_id, link="https://google.com")},
        {"text": "YouTube", "url": url_for("click_link", scan_id=scan_id, link="https://youtube.com")},
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
    # host=0.0.0.0 so phones on same Wi-Fi can connect
    app.run(host="0.0.0.0", port=PORT, debug=True)

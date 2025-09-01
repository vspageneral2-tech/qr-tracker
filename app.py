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

        # fetch label + links
        c.execute("SELECT qr_label, links_json FROM qr_configs WHERE scan_id=?", (scan_id,))
        row = c.fetchone()
        qr_label, links_json = (row or [None, ""])
        links = []
        try:
            import json
            links = json.loads(links_json) if links_json else []
        except Exception:
            pass

    # If only 1 link → auto redirect
    if len(links) == 1:
        target = links[0]["target"]
        # also log click
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO clicks (scan_id, link, timestamp) VALUES (?, ?, ?)",
                      (scan_id, target, datetime.now().isoformat()))
            conn.commit()
        return redirect(target)

    # Otherwise show landing page with multiple options
    # Convert into clickable URLs
    link_objs = [
        {"text": l["text"], "url": url_for("click_link", scan_id=scan_id, link=l["target"])}
        for l in links
    ]
    return render_template("scan.html", links=link_objs, qr_label=qr_label)



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
from flask import request

# ---- Delete a saved QR (optionally also delete its logs) ----
@app.route("/admin/delete-qr/<scan_id>", methods=["POST"])
def delete_qr(scan_id):
    delete_logs = request.form.get("delete_logs") == "1"
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # remove QR image file if present
        row = conn.execute("SELECT qr_image_path FROM qr_configs WHERE scan_id=?", (scan_id,)).fetchone()
        if row and row[0]:
            try:
                # row[0] is like 'static/qrs/....png'
                os.remove(row[0])
            except Exception:
                pass

        # delete from qr_configs
        c.execute("DELETE FROM qr_configs WHERE scan_id=?", (scan_id,))

        if delete_logs:
            c.execute("DELETE FROM scans  WHERE scan_id=?", (scan_id,))
            c.execute("DELETE FROM clicks WHERE scan_id=?", (scan_id,))
        conn.commit()
    return redirect(url_for("admin"))

# ---- Delete a single scan row by ID ----
@app.route("/admin/delete-scan/<int:scan_row_id>", methods=["POST"])
def delete_scan_row(scan_row_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_row_id,))
        conn.commit()
    return redirect(url_for("admin"))

# ---- Delete a single click row by ID ----
@app.route("/admin/delete-click/<int:click_row_id>", methods=["POST"])
def delete_click_row(click_row_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM clicks WHERE id=?", (click_row_id,))
        conn.commit()
    return redirect(url_for("admin"))

# ---- Bulk clear all scans ----
@app.route("/admin/clear-scans", methods=["POST"])
def clear_scans():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
    return redirect(url_for("admin"))

# ---- Bulk clear all clicks ----
@app.route("/admin/clear-clicks", methods=["POST"])
def clear_clicks():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM clicks")
        conn.commit()
    return redirect(url_for("admin"))

from flask import Response
from datetime import datetime, timedelta
import csv
import io
import json

def _range_start_utc(days: int) -> str:
    """Return ISO string (UTC) for start of range 'days' ago."""
    dt = datetime.utcnow() - timedelta(days=days-1)  # include today
    return dt.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

@app.route("/analytics")
def analytics():
    # Query params
    rng = request.args.get("range", "30")  # "7" | "30" | "90"
    try:
        days = int(rng)
        if days not in (7, 30, 90):
            days = 30
    except Exception:
        days = 30

    focus_scan_id = request.args.get("scan_id")  # for per-link chart (optional)
    start_iso = _range_start_utc(days)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # Totals (within range)
        total_qrs = conn.execute("SELECT COUNT(*) AS c FROM qr_configs").fetchone()["c"]
        total_scans = conn.execute("""
            SELECT COUNT(*) AS c FROM scans WHERE timestamp >= ?
        """, (start_iso,)).fetchone()["c"]
        total_clicks = conn.execute("""
            SELECT COUNT(*) AS c FROM clicks WHERE timestamp >= ?
        """, (start_iso,)).fetchone()["c"]

        # Per-QR scans & clicks (within range), include QRs with zero activity
        per_qr = conn.execute(f"""
            SELECT
              qc.scan_id,
              qc.qr_label,
              qc.created_at,
              COALESCE(s.cnt, 0) AS scans,
              COALESCE(k.cnt, 0) AS clicks
            FROM qr_configs qc
            LEFT JOIN (
              SELECT scan_id, COUNT(*) AS cnt
              FROM scans
              WHERE timestamp >= ?
              GROUP BY scan_id
            ) s USING (scan_id)
            LEFT JOIN (
              SELECT scan_id, COUNT(*) AS cnt
              FROM clicks
              WHERE timestamp >= ?
              GROUP BY scan_id
            ) k USING (scan_id)
            ORDER BY qc.created_at DESC
        """, (start_iso, start_iso)).fetchall()

        # Daily scans/clicks (range days, UTC date)
        daily_scans = conn.execute("""
            SELECT substr(timestamp,1,10) AS day, COUNT(*) AS cnt
            FROM scans
            WHERE timestamp >= ?
            GROUP BY day
            ORDER BY day ASC
        """, (start_iso,)).fetchall()

        daily_clicks = conn.execute("""
            SELECT substr(timestamp,1,10) AS day, COUNT(*) AS cnt
            FROM clicks
            WHERE timestamp >= ?
            GROUP BY day
            ORDER BY day ASC
        """, (start_iso,)).fetchall()

        # List of QRs to populate dropdown
        qr_list = conn.execute("""
            SELECT scan_id, qr_label
            FROM qr_configs
            ORDER BY created_at DESC
        """).fetchall()

        # Per-link analytics for a chosen QR (within range)
        per_link_rows = []
        link_map = {}
        if focus_scan_id:
            cfg = conn.execute("SELECT links_json FROM qr_configs WHERE scan_id = ?", (focus_scan_id,)).fetchone()
            if cfg and cfg["links_json"]:
                try:
                    for l in json.loads(cfg["links_json"]):
                        link_map[l["target"]] = l.get("text") or l["target"]
                except Exception:
                    pass

            per_link = conn.execute("""
                SELECT link, COUNT(*) AS cnt
                FROM clicks
                WHERE scan_id = ? AND timestamp >= ?
                GROUP BY link
                ORDER BY cnt DESC
            """, (focus_scan_id, start_iso)).fetchall()

            for r in per_link:
                label = link_map.get(r["link"], r["link"])
                per_link_rows.append({"link": r["link"], "label": label, "cnt": r["cnt"]})

    # Build view models
    per_qr_rows = []
    for r in per_qr:
        scans = (r["scans"] or 0)
        clicks = (r["clicks"] or 0)
        ctr = f"{(clicks / scans * 100):.1f}%" if scans > 0 else "—"
        per_qr_rows.append({
            "scan_id": r["scan_id"],
            "qr_label": r["qr_label"],
            "created_local": time_ist(r["created_at"]) if r["created_at"] else "",
            "scans": scans,
            "clicks": clicks,
            "ctr": ctr,
        })

    overall_ctr = f"{(total_clicks / total_scans * 100):.1f}%" if total_scans > 0 else "—"

    # Serialize for charts
    daily_scans_list = [dict(x) for x in daily_scans]
    daily_clicks_list = [dict(x) for x in daily_clicks]
    qr_list_simple = [dict(x) for x in qr_list]

    return render_template(
        "analytics.html",
        range_days=days,
        total_qrs=total_qrs,
        total_scans=total_scans,
        total_clicks=total_clicks,
        overall_ctr=overall_ctr,
        per_qr_rows=per_qr_rows,
        daily_scans=daily_scans_list,
        daily_clicks=daily_clicks_list,
        qr_list=qr_list_simple,
        focus_scan_id=focus_scan_id,
        per_link_rows=per_link_rows
    )

# ---------- CSV Exports ----------
def _csv_response(filename: str, rows: list, headers: list):
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(headers)
    for r in rows:
        cw.writerow([r.get(h, "") for h in headers])
    out = si.getvalue()
    resp = Response(out, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp

@app.route("/analytics/export/per_qr.csv")
def export_per_qr_csv():
    rng = request.args.get("range", "30")
    try:
        days = int(rng)
        if days not in (7, 30, 90): days = 30
    except Exception:
        days = 30
    start_iso = _range_start_utc(days)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT
              qc.scan_id,
              qc.qr_label,
              qc.created_at,
              COALESCE(s.cnt, 0) AS scans,
              COALESCE(k.cnt, 0) AS clicks
            FROM qr_configs qc
            LEFT JOIN (SELECT scan_id, COUNT(*) AS cnt FROM scans WHERE timestamp >= ? GROUP BY scan_id) s USING (scan_id)
            LEFT JOIN (SELECT scan_id, COUNT(*) AS cnt FROM clicks WHERE timestamp >= ? GROUP BY scan_id) k USING (scan_id)
            ORDER BY qc.created_at DESC
        """, (start_iso, start_iso)).fetchall()

    payload = []
    for r in rows:
        scans = r["scans"] or 0
        clicks = r["clicks"] or 0
        ctr = (clicks / scans * 100) if scans > 0 else None
        payload.append({
            "scan_id": r["scan_id"],
            "qr_label": r["qr_label"],
            "created_at": r["created_at"],
            "scans": scans,
            "clicks": clicks,
            "ctr_percent": f"{ctr:.1f}" if ctr is not None else ""
        })
    return _csv_response(f"per_qr_{days}d.csv", payload,
                         ["scan_id", "qr_label", "created_at", "scans", "clicks", "ctr_percent"])

@app.route("/analytics/export/daily.csv")
def export_daily_csv():
    rng = request.args.get("range", "30")
    try:
        days = int(rng)
        if days not in (7, 30, 90): days = 30
    except Exception:
        days = 30
    start_iso = _range_start_utc(days)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        scans = conn.execute("""
            SELECT substr(timestamp,1,10) AS day, COUNT(*) AS scans
            FROM scans WHERE timestamp >= ?
            GROUP BY day ORDER BY day ASC
        """, (start_iso,)).fetchall()
        clicks = conn.execute("""
            SELECT substr(timestamp,1,10) AS day, COUNT(*) AS clicks
            FROM clicks WHERE timestamp >= ?
            GROUP BY day ORDER BY day ASC
        """, (start_iso,)).fetchall()

    # merge by date
    by_day = {}
    for r in scans: by_day[r["day"]] = {"day": r["day"], "scans": r["scans"], "clicks": 0}
    for r in clicks:
        if r["day"] in by_day: by_day[r["day"]]["clicks"] = r["clicks"]
        else: by_day[r["day"]] = {"day": r["day"], "scans": 0, "clicks": r["clicks"]}
    rows = [by_day[k] for k in sorted(by_day.keys())]
    return _csv_response(f"daily_{days}d.csv", rows, ["day", "scans", "clicks"])

@app.route("/analytics/export/per_link.csv")
def export_per_link_csv():
    rng = request.args.get("range", "30")
    try:
        days = int(rng)
        if days not in (7, 30, 90): days = 30
    except Exception:
        days = 30
    start_iso = _range_start_utc(days)
    scan_id = request.args.get("scan_id")
    if not scan_id:
        return Response("scan_id is required", status=400)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cfg = conn.execute("SELECT links_json FROM qr_configs WHERE scan_id=?", (scan_id,)).fetchone()
        link_map = {}
        if cfg and cfg["links_json"]:
            try:
                for l in json.loads(cfg["links_json"]):
                    link_map[l["target"]] = l.get("text") or l["target"]
            except Exception:
                pass

        rows = conn.execute("""
            SELECT link, COUNT(*) AS clicks
            FROM clicks
            WHERE scan_id = ? AND timestamp >= ?
            GROUP BY link
            ORDER BY clicks DESC
        """, (scan_id, start_iso)).fetchall()

    payload = []
    for r in rows:
        payload.append({
            "scan_id": scan_id,
            "link_text": link_map.get(r["link"], r["link"]),
            "link_url": r["link"],
            "clicks": r["clicks"],
        })
    return _csv_response(f"per_link_{scan_id}_{days}d.csv", payload,
                         ["scan_id", "link_text", "link_url", "clicks"])


# -------------------
# Run (local dev)
# -------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)

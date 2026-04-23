from flask import Flask, request, render_template_string, send_file, jsonify, redirect, session
from threading import Lock
from openpyxl import Workbook
from werkzeug.security import generate_password_hash, check_password_hash
import io
from datetime import datetime
import secrets
import os
import uuid
import sqlite3
import json

app = Flask(__name__)

@app.route("/")
def index():
    return redirect("/login")

@app.route('/sw.js')
def sw():
    return app.send_static_file('sw.js')

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')


# --- Безопасность и Конфигурация ---
# Используем переменную окружения SECRET_KEY (обязательно задать на Render!)
_env_key = os.environ.get('SECRET_KEY')
if _env_key:
    app.secret_key = _env_key
else:
    secret_file = os.path.join(os.path.dirname(__file__), '.secret_key')
    if os.path.exists(secret_file):
        with open(secret_file, 'r') as f:
            app.secret_key = f.read().strip()
    else:
        app.secret_key = secrets.token_hex(32)
        with open(secret_file, 'w') as f:
            f.write(app.secret_key)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True
)

# Генерация CSRF
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    if request.method == "POST":
        # Skip CSRF for some routes if necessary (e.g. webhooks), but here we want it everywhere
        token = session.get('csrf_token', None)
        # Check both form data and a custom header for AJAX/JSON requests
        sent_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or token != sent_token:
            return "CSRF Error: Неверный токен", 403

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ============== БАЗА ДАННЫХ ==============
DATABASE_URL = os.environ.get('DATABASE_URL', '')

def _get_db():
    url = DATABASE_URL
    if url.startswith('postgres'):
        import psycopg2
        url = url.replace('postgres://', 'postgresql://', 1)
        conn = psycopg2.connect(url)
        return conn, 'pg'
    path = os.path.join(os.path.dirname(__file__), 'data.db')
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn, 'sqlite'

def _ph(db_type):
    return '%s' if db_type == 'pg' else '?'

def init_db():
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS inventory (
            location TEXT NOT NULL, name TEXT NOT NULL, count REAL NOT NULL DEFAULT 0,
            PRIMARY KEY (location, name))''')
        cur.execute('''CREATE TABLE IF NOT EXISTS history_items (
            id TEXT PRIMARY KEY, location TEXT NOT NULL, name TEXT NOT NULL,
            text TEXT NOT NULL, count REAL NOT NULL, username TEXT NOT NULL, timestamp TEXT NOT NULL)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'operator')''')
        cur.execute('''CREATE TABLE IF NOT EXISTS push_subscriptions (subscription TEXT PRIMARY KEY)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS pending_requests (
            request_id TEXT PRIMARY KEY, username TEXT NOT NULL, location TEXT NOT NULL, timestamp TEXT NOT NULL)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS custom_products (
            location TEXT NOT NULL, category TEXT NOT NULL, name TEXT NOT NULL,
            code TEXT, unit TEXT DEFAULT 'шт', removed INTEGER DEFAULT 0,
            PRIMARY KEY (location, category, name))''')
        conn.commit()
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'SuperAdmin!2026')
        if db_type == 'pg':
            cur.execute(f'INSERT INTO users (username, password_hash, role) VALUES ({p},{p},{p}) ON CONFLICT DO NOTHING',
                        ('admin', generate_password_hash(admin_pass), 'admin'))
        else:
            cur.execute(f'INSERT OR IGNORE INTO users (username, password_hash, role) VALUES ({p},{p},{p})',
                        ('admin', generate_password_hash(admin_pass), 'admin'))
        conn.commit()
    finally:
        conn.close()

# --- inventory ---
def db_get_inventory():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT location, name, count FROM inventory')
        return {(r[0], r[1]): r[2] for r in cur.fetchall()}
    finally:
        conn.close()

def db_update_inventory(location, name, delta):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        if db_type == 'pg':
            cur.execute(f'INSERT INTO inventory (location,name,count) VALUES ({p},{p},{p}) ON CONFLICT (location,name) DO UPDATE SET count=inventory.count+EXCLUDED.count',
                        (location, name, delta))
        else:
            cur.execute(f'INSERT INTO inventory (location,name,count) VALUES ({p},{p},{p}) ON CONFLICT (location,name) DO UPDATE SET count=count+excluded.count',
                        (location, name, delta))
        conn.commit()
    finally:
        conn.close()

def db_revert_inventory(location, name, count):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'UPDATE inventory SET count=count-{p} WHERE location={p} AND name={p}', (count, location, name))
        conn.commit()
    finally:
        conn.close()

def db_clear_inventory():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('DELETE FROM inventory')
        cur.execute('DELETE FROM history_items')
        conn.commit()
    finally:
        conn.close()

# --- history ---
def db_get_history():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id, location, name, text, count, username, timestamp FROM history_items ORDER BY timestamp')
        result = {}
        for r in cur.fetchall():
            key = (r[1], r[2])
            result.setdefault(key, []).append({'id': r[0], 'text': r[3], 'count': r[4], 'user': r[5], 'timestamp': r[6]})
        return result
    finally:
        conn.close()

def db_add_history(location, name, item):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'INSERT INTO history_items (id,location,name,text,count,username,timestamp) VALUES ({p},{p},{p},{p},{p},{p},{p})',
                    (item['id'], location, name, item['text'], item['count'], item['user'], item['timestamp']))
        conn.commit()
    finally:
        conn.close()

def db_delete_history_item(hist_id):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'SELECT count, username, location, name FROM history_items WHERE id={p}', (hist_id,))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(f'DELETE FROM history_items WHERE id={p}', (hist_id,))
        conn.commit()
        return row[0], row[1], row[2], row[3]
    finally:
        conn.close()

# --- users ---
def db_get_user(username):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'SELECT password_hash, role FROM users WHERE username={p}', (username,))
        row = cur.fetchone()
        return {'password': row[0], 'role': row[1]} if row else None
    finally:
        conn.close()

def db_get_all_users():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT username, role FROM users')
        return [(r[0], r[1]) for r in cur.fetchall()]
    finally:
        conn.close()

def db_create_user(username, password_hash, role='operator'):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        if db_type == 'pg':
            cur.execute(f'INSERT INTO users (username,password_hash,role) VALUES ({p},{p},{p}) ON CONFLICT DO NOTHING', (username, password_hash, role))
        else:
            cur.execute(f'INSERT OR IGNORE INTO users (username,password_hash,role) VALUES ({p},{p},{p})', (username, password_hash, role))
        conn.commit()
    finally:
        conn.close()

def db_delete_user(username):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'DELETE FROM users WHERE username={p}', (username,))
        conn.commit()
    finally:
        conn.close()

# --- push subscriptions ---
def db_get_subscriptions():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT subscription FROM push_subscriptions')
        return [json.loads(r[0]) for r in cur.fetchall()]
    finally:
        conn.close()

def db_add_subscription(sub):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        if db_type == 'pg':
            cur.execute(f'INSERT INTO push_subscriptions (subscription) VALUES ({p}) ON CONFLICT DO NOTHING', (json.dumps(sub),))
        else:
            cur.execute(f'INSERT OR IGNORE INTO push_subscriptions (subscription) VALUES ({p})', (json.dumps(sub),))
        conn.commit()
    finally:
        conn.close()

def db_remove_subscription(sub):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'DELETE FROM push_subscriptions WHERE subscription={p}', (json.dumps(sub),))
        conn.commit()
    finally:
        conn.close()

# --- pending requests ---
def db_get_pending():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT request_id, username, location, timestamp FROM pending_requests')
        return {r[0]: {'user': r[1], 'location': r[2], 'timestamp': r[3]} for r in cur.fetchall()}
    finally:
        conn.close()

def db_add_pending(request_id, username, location, timestamp):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'INSERT INTO pending_requests (request_id,username,location,timestamp) VALUES ({p},{p},{p},{p})',
                    (request_id, username, location, timestamp))
        conn.commit()
    finally:
        conn.close()

def db_delete_pending(request_id):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        cur.execute(f'DELETE FROM pending_requests WHERE request_id={p}', (request_id,))
        conn.commit()
    finally:
        conn.close()

# --- custom products ---
def db_get_custom_products():
    conn, _ = _get_db()
    try:
        cur = conn.cursor()
        cur.execute('SELECT location, category, name, code, unit, removed FROM custom_products')
        return cur.fetchall()
    finally:
        conn.close()

def db_upsert_product(location, category, name, code, unit, removed=0):
    conn, db_type = _get_db()
    p = _ph(db_type)
    try:
        cur = conn.cursor()
        if db_type == 'pg':
            cur.execute(f'INSERT INTO custom_products (location,category,name,code,unit,removed) VALUES ({p},{p},{p},{p},{p},{p}) ON CONFLICT (location,category,name) DO UPDATE SET code=EXCLUDED.code,unit=EXCLUDED.unit,removed=EXCLUDED.removed',
                        (location, category, name, code, unit, removed))
        else:
            cur.execute(f'INSERT OR REPLACE INTO custom_products (location,category,name,code,unit,removed) VALUES ({p},{p},{p},{p},{p},{p})',
                        (location, category, name, code, unit, removed))
        conn.commit()
    finally:
        conn.close()

init_db()

# Защита от брутфорса
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 минут

inventory_lock = Lock()
users_lock = Lock()

# ============== PUSH-УВЕДОМЛЕНИЯ (Web Push + VAPID) ==============
VAPID_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFnsPC4nmBJ1Cz1DwiBw+Oxw6ZCB2dUzwGCnRjcmkWEaoAoGCCqGSM49
AwEHoUQDQgAEaw/dxmVseO6eK2OszEWRWG0xuzQJ//WfQ6I0TeMkNUEmpmIxA7EU
borDgJpEkcgUuXqekcCwCo/2n5uJ+ImUkg==
-----END EC PRIVATE KEY-----"""
VAPID_PUBLIC_KEY = "BGsP3cZlbHjunitjrMxFkVhtMbs0Cf_1n0OiNE3jJDVBJqZiMQOxFG6Kw4CaRJHIFLl6npHAsAqP9p-bifiJlJI"
VAPID_CLAIMS = {"sub": "mailto:admin@revision-app.app"}

def send_push_notification(title, body):
    from pywebpush import webpush, WebPushException
    subs = db_get_subscriptions()
    for sub in subs:
        try:
            webpush(
                subscription_info=sub,
                data=json.dumps({"title": title, "body": body}),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
        except WebPushException as e:
            if '410' in str(e) or '404' in str(e):
                db_remove_subscription(sub)
            else:
                print(f"Push error: {e}")

# ПОЛНЫЙ СЛОВАРЬ ТОВАРОВ (динамически из шаблона template.xlsx)
GLOBAL_PRODUCTS = {}

try:
    import openpyxl
    file_path = os.path.join(os.path.dirname(__file__), 'template.xlsx')
    if os.path.exists(file_path):
        wb_temp = openpyxl.load_workbook(file_path, data_only=True)
        ws_temp = wb_temp.active
        current_cat = 'Разное'
        
        for row in ws_temp.iter_rows(values_only=True):
            code_raw = row[1]
            name_raw = row[2]
            unit_raw = row[5]
            
            if code_raw is not None and isinstance(code_raw, str) and not name_raw:
                val = code_raw.strip()
                if val and not val.startswith('Дата печати'):
                    current_cat = val
                    if current_cat not in GLOBAL_PRODUCTS:
                        GLOBAL_PRODUCTS[current_cat] = {}
                continue
            
            if code_raw is not None and name_raw is not None and str(code_raw).strip() != 'Код' and str(code_raw).strip() != 'Товар':
                code = str(code_raw).strip()
                name = str(name_raw).strip()
                unit = str(unit_raw).strip() if unit_raw else 'шт'
                
                if current_cat not in GLOBAL_PRODUCTS:
                    GLOBAL_PRODUCTS[current_cat] = {}
                
                GLOBAL_PRODUCTS[current_cat][name] = {"unit": unit, "code": code}
except Exception as e:
    print(f"Error loading products from template: {e}")

BASE_LOCATIONS = ["Склад", "Кухня", "Островок"]

def get_locations():
    locs = {}
    for location in BASE_LOCATIONS:
        locs[location] = {}
        for category, products in GLOBAL_PRODUCTS.items():
            locs[location][category] = dict(products)
    for row in db_get_custom_products():
        location, category, name, code, unit, removed = row
        if location not in locs:
            locs[location] = {}
        if removed:
            if category in locs[location] and name in locs[location][category]:
                del locs[location][category][name]
                if not locs[location][category]:
                    del locs[location][category]
        else:
            locs[location].setdefault(category, {})[name] = {'code': code or '', 'unit': unit or 'шт'}
    return locs

# ============== АВТОРИЗАЦИЯ ==============
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    now = datetime.now().timestamp()
    
    # Check lockout
    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]
        if attempts >= MAX_ATTEMPTS and now - last_time < LOCKOUT_TIME:
            return render_template_string(login_html, error=f"⚠️ Слишком много попыток. Попробуйте через {int((LOCKOUT_TIME - (now - last_time))/60)} мин.")
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db_get_user(username)
        user_found = user is not None and check_password_hash(user['password'], password)

        if user_found:
            login_attempts.pop(ip, None)
            session.clear()
            session['username'] = username
            session['role'] = user['role']
            generate_csrf_token()
            return redirect('/admin' if user['role'] == 'admin' else '/revision')
        else:
            attempts, last_time = login_attempts.get(ip, (0, 0))
            login_attempts[ip] = (attempts + 1, now)
            return render_template_string(login_html, error="❌ Неверный логин или пароль")
            
    return render_template_string(login_html, now=datetime.now().strftime("%d.%m %H:%M"))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

revision_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Ревизия</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f0c29">
<link rel="icon" href="/static/icon-512.png" type="image/png">
<link rel="apple-touch-icon" href="/static/icon-512.png">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
:root {
    --bg1: #0f0c29; --bg2: #302b63; --bg3: #24243e;
    --accent: #818cf8; --accent2: #a855f7;
    --card: rgba(255,255,255,0.07);
    --card-border: rgba(255,255,255,0.12);
    --text: rgba(255,255,255,0.92);
    --muted: rgba(255,255,255,0.4);
    --success: #34d399; --danger: #f87171;
}
body {
    font-family: 'Outfit', sans-serif;
    background: linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
    min-height: 100vh;
    color: var(--text);
    padding-bottom: 100px;
    position: relative;
}
/* Blobs */
.blob { position: fixed; border-radius: 50%; filter: blur(90px); opacity: 0.15; pointer-events: none; animation: bfloat 12s ease-in-out infinite; }
.blob1 { width: 500px; height: 500px; background: #6366f1; top: -150px; left: -150px; }
.blob2 { width: 400px; height: 400px; background: #a855f7; bottom: -100px; right: -100px; animation-delay: -4s; }
@keyframes bfloat { 0%,100% { transform: translate(0,0); } 50% { transform: translate(20px,-20px); } }

/* Header */
header {
    background: rgba(255,255,255,0.06);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--card-border);
    padding: 14px 20px;
    position: sticky; top: 0; z-index: 100;
    display: flex; justify-content: space-between; align-items: center;
}
.header-brand { display: flex; align-items: center; gap: 10px; }
.header-icon {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
}
header h1 { font-size: 18px; font-weight: 700; color: white; letter-spacing: -0.3px; }
.header-actions { display: flex; gap: 8px; }
.btn-icon {
    background: rgba(255,255,255,0.1);
    border: 1px solid var(--card-border);
    padding: 8px 14px;
    border-radius: 10px;
    color: white;
    font-size: 13px;
    font-weight: 600;
    font-family: 'Outfit', sans-serif;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
    display: inline-block;
}
.btn-icon:active { transform: scale(0.95); }

/* Location Tabs */
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 14px 20px;
    gap: 10px;
    scrollbar-width: none;
}
.tabs::-webkit-scrollbar { display: none; }
.tab {
    padding: 8px 20px;
    background: rgba(255,255,255,0.07);
    border: 1px solid var(--card-border);
    border-radius: 50px;
    font-weight: 600;
    color: var(--muted);
    white-space: nowrap;
    font-size: 14px;
    text-decoration: none;
    transition: all 0.2s;
    font-family: 'Outfit', sans-serif;
}
.tab.active {
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border-color: transparent;
    box-shadow: 0 4px 16px rgba(99,102,241,0.4);
}

/* Container & Search */
.container { padding: 0 20px; position: relative; z-index: 1; }
.search-box { position: sticky; top: 65px; z-index: 90; padding: 10px 0; }
.search-box input {
    width: 100%;
    padding: 13px 18px;
    border: 1.5px solid var(--card-border);
    border-radius: 14px;
    background: rgba(255,255,255,0.08);
    backdrop-filter: blur(20px);
    color: white;
    font-size: 15px;
    font-family: 'Outfit', sans-serif;
    outline: none;
    transition: all 0.3s;
}
.search-box input::placeholder { color: var(--muted); }
.search-box input:focus { border-color: rgba(99,102,241,0.6); background: rgba(255,255,255,0.11); }

/* Category headers */
.product-group { margin-bottom: 24px; }
.product-group h3 {
    margin: 16px 0 10px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    font-weight: 700;
}

/* Product Items */
.product-item {
    background: var(--card);
    border: 1px solid var(--card-border);
    padding: 16px;
    border-radius: 16px;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    transition: transform 0.15s cubic-bezier(0.34,1.56,0.64,1), background 0.2s, box-shadow 0.2s;
    animation: itemIn 0.4s ease both;
}
.product-item:active { transform: scale(0.97); }
.product-item:hover { background: rgba(255,255,255,0.1); box-shadow: 0 4px 20px rgba(0,0,0,0.2); }
@keyframes itemIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}
.p-name { font-weight: 600; font-size: 15px; color: white; }
.p-meta { font-size: 12px; color: var(--muted); margin-top: 3px; }
.badge {
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    padding: 5px 12px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 700;
    min-width: 36px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(99,102,241,0.4);
}

/* Bottom Finish Button */
.finish-btn {
    position: fixed;
    bottom: 20px; left: 20px; right: 20px;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border: none;
    padding: 18px;
    border-radius: 18px;
    font-size: 16px;
    font-weight: 700;
    font-family: 'Outfit', sans-serif;
    box-shadow: 0 12px 32px rgba(99,102,241,0.5);
    z-index: 90;
    transition: transform 0.2s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.2s;
    letter-spacing: 0.3px;
}
.finish-btn:active { transform: scale(0.97); box-shadow: 0 6px 16px rgba(99,102,241,0.4); }

/* Modal */
.modal {
    display: none; position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.7);
    backdrop-filter: blur(8px);
    z-index: 1000; align-items: flex-end;
}
.modal.active { display: flex; }
.modal-content {
    background: linear-gradient(180deg, #1e1b4b, #0f0c29);
    border: 1px solid rgba(255,255,255,0.12);
    width: 100%;
    border-radius: 28px 28px 0 0;
    padding: 24px 24px 36px;
    box-shadow: 0 -20px 60px rgba(0,0,0,0.6);
    animation: slideUp 0.35s cubic-bezier(0.16, 1, 0.3, 1);
}
@keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
.calc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.calc-title { font-size: 17px; font-weight: 700; color: white; max-width: 78%; line-height: 1.3; }
.close-btn {
    width: 32px; height: 32px;
    background: rgba(255,255,255,0.1);
    border: none; border-radius: 50%;
    color: white; font-size: 16px; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
}
.calc-display {
    width: 100%;
    font-size: 36px;
    padding: 10px 12px;
    text-align: right;
    border: none;
    border-bottom: 1.5px solid rgba(255,255,255,0.15);
    margin-bottom: 20px;
    font-family: 'Outfit', monospace;
    font-weight: 600;
    color: #a5b4fc;
    background: transparent;
    outline: none;
}
.calc-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.c-btn {
    padding: 16px 8px;
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,0.08);
    font-size: 20px;
    font-weight: 600;
    font-family: 'Outfit', sans-serif;
    background: rgba(255,255,255,0.06);
    color: white;
    touch-action: manipulation;
    transition: transform 0.1s cubic-bezier(0.34,1.56,0.64,1), background 0.15s;
}
.c-btn:active { transform: scale(0.92); background: rgba(255,255,255,0.12); }
.op-btn { background: rgba(99,102,241,0.2); color: #a5b4fc; border-color: rgba(99,102,241,0.3); }
.op-btn:active { background: rgba(99,102,241,0.35); }
.submit-btn {
    grid-column: span 2;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border-color: transparent;
    box-shadow: 0 6px 20px rgba(99,102,241,0.4);
}
.submit-btn:active { transform: scale(0.96); }
.total-row { margin-top: 14px; text-align: center; font-size: 15px; color: var(--muted); }
.highlight { color: #a5b4fc; font-weight: 700; font-size: 18px; }
.history-log {
    margin-top: 16px; background: rgba(255,255,255,0.04); border: 1px solid var(--card-border);
    padding: 10px 12px; border-radius: 12px; font-size: 12px;
    color: var(--muted); max-height: 90px; overflow-y: auto;
}
.history-item { border-bottom: 1px solid rgba(255,255,255,0.05); padding: 4px 0; }
.values-list {
    margin: 10px 0; max-height: 100px; overflow-y: auto;
    border: 1px solid var(--card-border); border-radius: 10px;
    background: rgba(255,255,255,0.04); display: none;
}
.value-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 14px; color: white;
}
.value-item:last-child { border-bottom: none; }
.del-val-btn { color: var(--danger); background: none; border: none; cursor: pointer; font-size: 18px; padding: 0 6px; }
.confirm-box { text-align: center; padding: 20px 0; border-radius: 28px; }
.confirm-box h2 { color: var(--accent); font-size: 22px; margin-bottom: 10px; }
.confirm-box p { color: var(--muted); margin-bottom: 24px; }
</style>
</head>
<body>
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="blob blob1"></div>
<div class="blob blob2"></div>

<header>
    <div class="header-brand">
        <div class="header-icon">🍔</div>
        <h1>Инвентаризация</h1>
    </div>
    <div class="header-actions">
        {% if role == 'admin' %}
        <a href="/admin"><button class="btn-icon">⚙️</button></a>
        {% endif %}
        <a href="/logout"><button class="btn-icon">Выход</button></a>
    </div>
</header>

<div class="tabs">
    <a href="/revision?location=Склад" class="tab {% if 'Склад' == current %}active{% endif %}">📦 Склад</a>
    <a href="/revision?location=Кухня" class="tab {% if 'Кухня' == current %}active{% endif %}">🍳 Кухня</a>
    <a href="/revision?location=Островок" class="tab {% if 'Островок' == current %}active{% endif %}">🏝 Островок</a>
</div>

<div class="container">
    <div class="search-box">
        <input type="text" id="search" placeholder="🔍 Поиск товара..." onkeyup="filterProducts()">
    </div>
    <div id="productList">
    {% for cat, products in locations[current].items() %}
      <div class="product-group">
      {% if 'НА ДАТУ:' in cat | upper %}
      <h3>НА ДАТУ: {{ now_date }}</h3>
      {% else %}
      <h3>{{cat}}</h3>
      {% endif %}
      {% for name, data in products.items() %}
      {% set qty = inventory.get((current, name), 0) %}
      {% set hist_list = history.get((current, name), []) %}
      <div class="product-item" data-name="{{name | lower}}" data-history='{{ hist_list | tojson }}' onclick="openCalc({{ current|tojson|safe }}, {{ name|tojson|safe }}, {{ data.unit|tojson|safe }}, this)" style="animation-delay: {{ loop.index * 0.03 }}s">
        <div>
            <div class="p-name">{{name}}</div>
            <div class="p-meta">{{data.unit}}</div>
        </div>
        {% if qty > 0%}<div class="badge">{{qty}}</div>{% endif %}
      </div>
      {% endfor %}
      </div>
    {% endfor %}
    </div>
</div>

<button class="finish-btn" onclick="requestFinish()">✅ Завершить ревизию</button>

<!-- Calculator Modal -->
<div class="modal" id="calcModal" onclick="if(event.target===this)closeCalc()">
<div class="modal-content">
    <div class="calc-header">
        <div class="calc-title" id="calcTitle"></div>
        <button class="close-btn" onclick="closeCalc()">✕</button>
    </div>
    <input type="text" id="calcDisplay" class="calc-display" readonly value="0">
    <div class="calc-grid">
        <button class="c-btn" onclick="num('7')">7</button>
        <button class="c-btn" onclick="num('8')">8</button>
        <button class="c-btn" onclick="num('9')">9</button>
        <button class="c-btn op-btn" onclick="setOp('/')">÷</button>
        <button class="c-btn" onclick="num('4')">4</button>
        <button class="c-btn" onclick="num('5')">5</button>
        <button class="c-btn" onclick="num('6')">6</button>
        <button class="c-btn op-btn" onclick="setOp('*')">×</button>
        <button class="c-btn" onclick="num('1')">1</button>
        <button class="c-btn" onclick="num('2')">2</button>
        <button class="c-btn" onclick="num('3')">3</button>
        <button class="c-btn op-btn" onclick="setOp('-')">−</button>
        <button class="c-btn" onclick="num('.')">.</button>
        <button class="c-btn" onclick="num('0')">0</button>
        <button class="c-btn" onclick="clr()">C</button>
        <button class="c-btn op-btn" onclick="setOp('+')">+</button>
        <button class="c-btn op-btn" onclick="calculate()">=</button>
        <button class="c-btn op-btn" style="font-size:15px" onclick="addToTotal()">Внести</button>
        <button class="c-btn submit-btn" onclick="saveResult()">СОХРАНИТЬ</button>
    </div>
    <div id="addedValuesList" class="values-list"></div>
    <div class="total-row">Итого: <span id="total" class="highlight">0</span> <span id="unit"></span></div>
    <div style="margin-top:12px;">
        <div style="font-size:11px;color:rgba(255,255,255,0.25);margin-bottom:6px;letter-spacing:0.5px;">ИСТОРИЯ</div>
        <div id="calcHistory" class="history-log"></div>
    </div>
</div>
</div>

<!-- Confirm Modal -->
<div class="modal" id="confirmModal">
<div class="modal-content">
    <div class="confirm-box">
        <h2>✅ Запрос отправлен</h2>
        <p>Ожидание подтверждения администратором...</p>
        <button class="finish-btn" style="position:static;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.15);box-shadow:none;" onclick="cancelRequest()">Отмена</button>
    </div>
</div>
</div>

<script>
let loc='', prod='', unit='';
let val='0', op=null, prev=null, total=0;
let addedValues = [];

function filterProducts(){
  const filter=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.product-item').forEach(item=>{
    item.style.display=item.getAttribute('data-name').includes(filter)?'flex':'none';
  });
  document.querySelectorAll('.product-group').forEach(group => {
     const vis = Array.from(group.querySelectorAll('.product-item')).filter(i => i.style.display !== 'none');
     group.style.display = vis.length > 0 ? 'block' : 'none';
  });
}

function openCalc(l,p,u, el){
  loc=l;prod=p;unit=u;total=0;val='0';op=null;prev=null;
  addedValues = [];
  renderValuesList();
  document.getElementById('calcTitle').innerText=p;
  document.getElementById('unit').innerText=u;
  document.getElementById('calcDisplay').value='0';
  document.getElementById('total').innerText='0';
  const hist = JSON.parse(el.getAttribute('data-history') || '[]');
  renderHistory(hist);
  document.getElementById('calcModal').classList.add('active');
}

function renderHistory(history) {
    const c = document.getElementById('calcHistory');
    if(history.length > 0) {
        c.innerHTML = history.map(h => {
             let text = '', id = null;
             if (typeof h === 'string') { text = h; } else { text = h.text; id = h.id; }
             let delBtn = id ? `<button class="del-val-btn" onclick="deleteHistoryItem('${id}', '${loc}', '${prod}')">×</button>` : '';
             return `<div class="history-item" style="display:flex;justify-content:space-between;"><span>${text}</span>${delBtn}</div>`;
        }).reverse().join('');
    } else { c.innerHTML = '<span style="opacity:0.4">История пуста</span>'; }
}

async function deleteHistoryItem(id, location, name) {
    if(!confirm('Удалить запись? Изменит остаток.')) return;
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
    const fd = new FormData();
    fd.append('id', id); fd.append('location', location); fd.append('name', name);
    const res = await fetch('/delete_history_api', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
        body: fd
    });
    if (res.ok) { window.location.reload(); } else { alert('Ошибка'); }
}

function closeCalc(){document.getElementById('calcModal').classList.remove('active');}
function num(n){if(val==='0'||val==='Error')val=n;else val+=n;document.getElementById('calcDisplay').value=val;}
function setOp(o){prev=parseFloat(val);val='0';op=o;}
function calculate(){if(op&&prev!=null){const cur=parseFloat(val);let r;
  switch(op){case '+':r=prev+cur;break;case '-':r=prev-cur;break;case '*':r=prev*cur;break;case '/':r=cur!==0?prev/cur:'Error';break;}
  val=r.toString();op=null;prev=null;document.getElementById('calcDisplay').value=val;}}
function clr(){val='0';prev=null;op=null;document.getElementById('calcDisplay').value='0';}

function addToTotal(){
    calculate();
    let n=parseFloat(val);
    if(!isNaN(n) && n !== 0){ addedValues.push(n); renderValuesList(); }
    val='0'; document.getElementById('calcDisplay').value='0';
}

function renderValuesList() {
    const list = document.getElementById('addedValuesList');
    if (addedValues.length === 0) {
        list.style.display = 'none'; list.innerHTML = ''; total = 0;
    } else {
        list.style.display = 'block';
        list.innerHTML = addedValues.map((v, i) => `<div class="value-item"><span>${v}</span><button class="del-val-btn" onclick="removeValue(${i})">×</button></div>`).join('');
        total = addedValues.reduce((a, b) => a + b, 0);
    }
    total = Math.round(total * 1000) / 1000;
    document.getElementById('total').innerText = total;
}

function removeValue(i) { addedValues.splice(i, 1); renderValuesList(); }

async function saveResult(){
  let n = 0;
  if (addedValues.length > 0) { n = total; } else { n = parseFloat(val); if (isNaN(n)) n = 0; }
  if(isNaN(n)||n<=0){alert('Введите корректное число');return;}
  const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
  const fd=new FormData(); fd.append('location',loc); fd.append('name',prod); fd.append('count',n);
  const res = await fetch('/add_api',{
    method:'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    body:fd
  });
  if(res.status === 403) { alert('Сессия истекла. Страница будет перезагружена.'); window.location.reload(); return; }
  if(!res.ok) { alert('Ошибка сохранения: ' + res.status); return; }
  closeCalc(); window.location.reload();
}

async function requestFinish(){
  const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
  await fetch('/request_finish?location=' + encodeURIComponent(loc||'Все'), {
      method:'POST',
      headers: { 'X-CSRF-Token': csrfToken }
  });
  document.getElementById('confirmModal').classList.add('active');
}

function cancelRequest(){ document.getElementById('confirmModal').classList.remove('active'); }
</script>
<script>
if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }
</script>
</body>
</html>'''

login_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Ревизия</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f0c29">
<link rel="icon" href="/static/icon-512.png" type="image/png">
<link rel="apple-touch-icon" href="/static/icon-512.png">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
:root {
    --accent: #818cf8;
    --accent2: #c084fc;
    --bg1: #0f0c29;
    --bg2: #302b63;
    --bg3: #24243e;
}
body {
    font-family: 'Outfit', sans-serif;
    background: linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    overflow: hidden;
}

/* Animated blobs */
.blob {
    position: fixed;
    border-radius: 50%;
    filter: blur(80px);
    opacity: 0.25;
    animation: float 8s ease-in-out infinite;
    pointer-events: none;
}
.blob1 { width: 400px; height: 400px; background: #6366f1; top: -100px; left: -100px; animation-delay: 0s; }
.blob2 { width: 350px; height: 350px; background: #a855f7; bottom: -80px; right: -80px; animation-delay: -3s; }
.blob3 { width: 250px; height: 250px; background: #06b6d4; top: 40%; left: 40%; animation-delay: -5s; }
@keyframes float {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(30px, -30px) scale(1.05); }
    66% { transform: translate(-20px, 20px) scale(0.95); }
}

/* Splash Screen */
#splash {
    position: fixed;
    inset: 0;
    background: linear-gradient(135deg, var(--bg1), var(--bg2), var(--bg3));
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    transition: opacity 0.8s ease, transform 0.8s ease;
}
#splash.hide {
    opacity: 0;
    transform: scale(1.05);
    pointer-events: none;
}
.splash-logo {
    width: 100px;
    height: 100px;
    background: rgba(255,255,255,0.1);
    backdrop-filter: blur(20px);
    border-radius: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 52px;
    border: 1.5px solid rgba(255,255,255,0.2);
    animation: logoIn 0.7s cubic-bezier(0.34, 1.56, 0.64, 1) both;
    box-shadow: 0 20px 60px rgba(99,102,241,0.4);
}
@keyframes logoIn {
    from { opacity: 0; transform: scale(0.5) rotate(-10deg); }
    to   { opacity: 1; transform: scale(1) rotate(0deg); }
}
.splash-title {
    color: white;
    font-size: 28px;
    font-weight: 700;
    margin-top: 24px;
    letter-spacing: -0.5px;
    animation: fadeUp 0.6s 0.3s ease both;
}
.splash-sub {
    color: rgba(255,255,255,0.5);
    font-size: 14px;
    margin-top: 8px;
    animation: fadeUp 0.6s 0.5s ease both;
}
@keyframes fadeUp {
    from { opacity: 0; transform: translateY(16px); }
    to   { opacity: 1; transform: translateY(0); }
}
.splash-bar {
    width: 180px;
    height: 3px;
    background: rgba(255,255,255,0.15);
    border-radius: 999px;
    margin-top: 40px;
    overflow: hidden;
    animation: fadeUp 0.6s 0.6s ease both;
}
.splash-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #6366f1, #a855f7);
    border-radius: 999px;
    animation: load 1.6s 0.4s ease-out both;
}
@keyframes load {
    from { width: 0%; }
    to   { width: 100%; }
}

/* Login Card */
.login-wrap {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: 400px;
    animation: cardIn 0.6s 0.1s cubic-bezier(0.34, 1.2, 0.64, 1) both;
    opacity: 0;
}
@keyframes cardIn {
    from { opacity: 0; transform: translateY(40px) scale(0.95); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
}
.login-box {
    background: rgba(255,255,255,0.08);
    backdrop-filter: blur(30px);
    -webkit-backdrop-filter: blur(30px);
    border: 1.5px solid rgba(255,255,255,0.15);
    padding: 40px 32px;
    border-radius: 28px;
    box-shadow: 0 30px 80px rgba(0,0,0,0.5);
}
.brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 32px;
}
.brand-icon {
    width: 52px;
    height: 52px;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    box-shadow: 0 8px 24px rgba(99,102,241,0.4);
}
.brand-text h1 {
    color: white;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.3px;
}
.brand-text p {
    color: rgba(255,255,255,0.4);
    font-size: 13px;
    margin-top: 1px;
}

.form-group { margin-bottom: 18px; }
.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: rgba(255,255,255,0.6);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.input-wrap { position: relative; }
.form-group input {
    width: 100%;
    padding: 14px 16px;
    border: 1.5px solid rgba(255,255,255,0.12);
    border-radius: 14px;
    font-size: 16px;
    font-family: 'Outfit', sans-serif;
    transition: all 0.3s ease;
    background: rgba(255,255,255,0.07);
    color: white;
    outline: none;
}
.form-group input::placeholder { color: rgba(255,255,255,0.25); }
.form-group input:focus {
    border-color: rgba(99,102,241,0.7);
    background: rgba(255,255,255,0.1);
    box-shadow: 0 0 0 4px rgba(99,102,241,0.15);
}
.btn {
    width: 100%;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border: none;
    padding: 16px;
    border-radius: 14px;
    font-weight: 700;
    cursor: pointer;
    font-size: 16px;
    font-family: 'Outfit', sans-serif;
    letter-spacing: 0.3px;
    transition: transform 0.15s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.2s ease;
    margin-top: 8px;
    box-shadow: 0 8px 24px rgba(99,102,241,0.4);
}
.btn:active { transform: scale(0.96); box-shadow: 0 4px 12px rgba(99,102,241,0.3); }
.btn:hover { transform: translateY(-1px); box-shadow: 0 12px 32px rgba(99,102,241,0.5); }
.error {
    color: #fca5a5;
    background: rgba(239,68,68,0.15);
    padding: 12px 16px;
    border-radius: 12px;
    margin-bottom: 18px;
    text-align: center;
    font-size: 14px;
    border: 1px solid rgba(239,68,68,0.3);
}
.version { text-align: center; color: rgba(255,255,255,0.2); font-size: 11px; margin-top: 24px; letter-spacing: 0.5px; }
</style>
</head>
<body>

<!-- Splash Screen -->
<div id="splash">
    <div class="splash-logo">🍔</div>
    <div class="splash-title">Ревизия</div>
    <div class="splash-sub">Система учета товаров</div>
    <div class="splash-bar"><div class="splash-bar-fill"></div></div>
</div>

<!-- Background Blobs -->
<div class="blob blob1"></div>
<div class="blob blob2"></div>
<div class="blob blob3"></div>

<div class="login-wrap">
<div class="login-box">
    <div class="brand">
        <div class="brand-icon">🍔</div>
        <div class="brand-text">
            <h1>Ревизия</h1>
            <p>Система учёта товаров</p>
        </div>
    </div>
    {% if error %}<div class="error">{{error}}</div>{% endif %}
    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group">
            <label>Логин</label>
            <input type="text" name="username" placeholder="Введите логин" required autocomplete="username">
        </div>
        <div class="form-group">
            <label>Пароль</label>
            <input type="password" name="password" placeholder="Введите пароль" required autocomplete="current-password">
        </div>
        <button class="btn" type="submit">Войти →</button>
    </form>
    <div class="version">{{ now }}</div>
</div>
</div>

<script>
setTimeout(() => {
    document.getElementById('splash').classList.add('hide');
    document.querySelector('.login-wrap').style.animationPlayState = 'running';
}, 1800);
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}
</script>
</body>
</html>'''

# ============== ПРОВЕРКА АВТОРИЗАЦИИ ==============
def require_login(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_admin(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ============== АДМИН ПАНЕЛЬ ==============
@app.route('/admin')
@require_admin
def admin_panel():
    user_list = db_get_all_users()
    html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Панель Администратора</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#f8fafc">
<link rel="icon" href="/static/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/static/icon.svg">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --bg-body: #f8fafc;
    --card-bg: #ffffff;
    --text-main: #0f172a;
    --text-muted: #64748b;
    --danger: #ef4444;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-body);
    margin: 0;
    padding: 0;
    color: var(--text-main);
    padding-bottom: 40px;
}
header {
    background: var(--card-bg);
    padding: 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    margin-bottom: 20px;
}
header h1 { margin: 0; font-size: 22px; color: var(--primary); }
.header-actions { display: flex; gap: 10px; margin-top: 15px; }
.btn {
    padding: 10px 16px;
    border: none;
    border-radius: 10px;
    font-weight: 500;
    cursor: pointer;
    font-size: 14px;
    transition: all 0.2s;
}
.btn-primary { background: var(--primary); color: white; }
.btn-danger { background: #fee2e2; color: var(--danger); }
.btn-outline { background: white; border: 1px solid #e2e8f0; color: var(--text-main); }
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 0 20px 20px;
    gap: 10px;
    scrollbar-width: none;
}
.tab-btn {
    padding: 10px 20px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 50px;
    white-space: nowrap;
    color: var(--text-muted);
    font-weight: 500;
}
.tab-btn.active {
    background: var(--primary);
    color: white;
    border-color: var(--primary);
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
}
.tab-content { display: none; padding: 0 20px; }
.tab-content.active { display: block; animation: fadeIn 0.3s; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

.card {
    background: var(--card-bg);
    padding: 24px;
    border-radius: 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    margin-bottom: 20px;
}
.card h2 { margin-top: 0; font-size: 18px; color: var(--text-main); margin-bottom: 20px; }
.form-input {
    width: 100%;
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 12px;
    margin-bottom: 15px;
    font-family: inherit;
}
.user-list { width: 100%; border-collapse: collapse; }
.user-list td { padding: 12px 0; border-bottom: 1px solid #f1f5f9; }

/* Product Delete UI */
.search-results {
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    margin-bottom: 15px;
    display: none;
}
.search-item { padding: 10px; cursor: pointer; border-bottom: 1px solid #f1f5f9; }
.search-item:hover { background: #f8fafc; }
.scope-selector { display: flex; flex-direction: column; gap: 10px; margin: 15px 0; display: none; }
.scope-option {
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
}
.scope-option.selected { border-color: var(--danger); background: #fef2f2; }
</style>
</head>
<body>
<header>
    <h1>👨‍💼 Панель Администратора</h1>
    <div class="header-actions">
        <button class="btn btn-primary" id="notifyBtn" onclick="subscribePush()">🔔 Уведомления</button>
        <a href="/revision"><button class="btn btn-primary">📊 Ревизия</button></a>
        <a href="/logout"><button class="btn btn-outline">Выход</button></a>
    </div>
</header>

<div class="tabs">
    <button class="tab-btn active" onclick="switchTab('users')">Пользователи</button>
    <button class="tab-btn" onclick="switchTab('products')">Товары</button>
    <button class="tab-btn" onclick="switchTab('requests')">Запросы</button>
</div>

<div id="users" class="tab-content active">
    <!-- User Management -->
    <div class="card">
        <h2>Создать оператора</h2>
        <form method="post" action="/admin/create_user">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input class="form-input" type="text" name="username" placeholder="Логин" required>
            <input class="form-input" type="password" name="password" placeholder="Пароль (опционально)">
            <button class="btn btn-primary" type="submit">Создать</button>
        </form>
    </div>
    <div class="card">
        <h2>Активные пользователи</h2>
        <table class="user-list">
        {% for user, role in users %}
        <tr>
            <td><strong>{{user}}</strong> <span style="color:var(--text-muted);font-size:12px;">{{role}}</span></td>
            <td align="right">
            {% if user != 'admin' %}
            <form method="post" action="/admin/delete_user" style="display:inline;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="username" value="{{ user }}">
            <button class="btn btn-danger" onclick="return confirm('Удалить?')">×</button>
            </form>
            {% endif %}
            </td>
        </tr>
        {% endfor %}
        </table>
    </div>
</div>

<div id="products" class="tab-content">
    
    <!-- Smart Delete -->
    <div class="card" style="border: 2px solid #fee2e2;">
        <h2 style="color:var(--danger)">🗑 Выборочное удаление</h2>
        <input type="text" id="pSearch" class="form-input" placeholder="Начните вводить название..." onkeyup="searchProd()">
        <div id="searchResults" class="search-results"></div>
        
        <div id="deleteScope" class="scope-selector">
            <h3 style="font-size:14px;margin:0;">Где удалить <b id="selectedProd"></b>?</h3>
            <div class="scope-option" onclick="toggleScope('global', this)" id="opt-global">
                <span>🌍 Везде (Глобально)</span>
            </div>
            <div style="font-size:12px;color:#999;margin-left:5px;">ИЛИ Выберите конкретно:</div>
            {% for loc in LOCATIONS %}
            <div class="scope-option location-opt" onclick="toggleScope({{ loc|tojson|safe }}, this)">
                <span>📍 {{loc}}</span>
            </div>
            {% endfor %}
            <button class="btn btn-danger" style="margin-top:10px;" onclick="confirmDelete()">Подтвердить удаление</button>
        </div>
    </div>

    <!-- Standard Edit -->
    <div class="card">
        <h2>Добавить / Удалить (Стандарт)</h2>
        <form method="post" action="/admin/edit_products">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div style="margin-bottom:15px; border: 1px solid #e2e8f0; padding: 10px; border-radius: 12px;">
                <label style="display:block; margin-bottom:10px; font-weight:600;">Где добавить/изменить?</label>
                <div style="display:flex; flex-direction:column; gap:8px;">
                     <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" id="addAllGlobal" onchange="toggleAllAdd(this)">
                        <strong>🌍 Везде (Глобально)</strong>
                    </label>
                    <div style="height:1px; background:#e2e8f0; margin:5px 0;"></div>
                    {% for loc in LOCATIONS %}
                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" name="locations" value="{{loc}}" class="add-loc-check">
                        <span>📍 {{loc}}</span>
                    </label>
                    {% endfor %}
                </div>
            </div>
            
            <input class="form-input" type="text" name="category" placeholder="Категория" required>
            <input class="form-input" type="text" name="name" placeholder="Название" required>
            <input class="form-input" type="text" name="code" placeholder="Код (Штрих-код)">
            <input class="form-input" type="text" name="unit" placeholder="Ед. изм. (напр. шт)">
            <button class="btn btn-primary" type="submit" name="action" value="add">Добавить / Обновить</button>
            <button class="btn btn-danger" type="submit" name="action" value="remove">Удалить</button>
        </form>
        <script>
        function toggleAllAdd(source) {
            document.querySelectorAll('.add-loc-check').forEach(c => {
                c.checked = source.checked;
            });
        }
        </script>
    </div>
</div>

<div id="requests" class="tab-content">
    <div class="card">
        <h2>Запросы на завершение</h2>
        {% if not pending_finish %}
        <p style="color:#999;text-align:center;">Нет ожидающих запросов</p>
        {% else %}
        {% for req_id, data in pending_finish.items() %}
        <div style="background:#f8fafc;padding:15px;border-radius:12px;margin-bottom:10px;">
            <div><strong>{{data.location}}</strong> <small>{{data.timestamp}}</small></div>
            <div style="color:#666;margin:5px 0;">от {{data.user}}</div>
            <div style="display:flex;gap:10px;margin-top:10px;">
                <form method="post" action="/admin/finish_confirm" style="width:100%">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="request_id" value="{{ req_id }}">
                    <button class="btn btn-primary" style="width:100%">Подтвердить</button>
                </form>
                 <form method="post" action="/admin/finish_cancel" style="width:100%">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="request_id" value="{{ req_id }}">
                    <button class="btn btn-danger" style="width:100%">Отклонить</button>
                </form>
            </div>
        </div>
        {% endfor %}
        {% endif %}
    </div>
</div>

<script>
function switchTab(t) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(t).classList.add('active');
    event.target.classList.add('active');
}

/* Delete Logic */
let selectedProduct = null;
let deleteScope = [];

async function searchProd() {
    const q = document.getElementById('pSearch').value;
    if(q.length < 2) { document.getElementById('searchResults').style.display='none'; return; }
    
    const res = await fetch('/admin/search_products?q='+encodeURIComponent(q));
    const list = await res.json();
    
    const div = document.getElementById('searchResults');
    div.innerHTML = '';
    div.style.display = list.length ? 'block' : 'none';
    
    list.forEach(p => {
        const el = document.createElement('div');
        el.className = 'search-item';
        el.innerText = p;
        el.onclick = () => selectForDelete(p);
        div.appendChild(el);
    });
}

function selectForDelete(name) {
    selectedProduct = name;
    document.getElementById('pSearch').value = name;
    document.getElementById('searchResults').style.display = 'none';
    document.getElementById('selectedProd').innerText = name;
    document.getElementById('deleteScope').style.display = 'flex';
    deleteScope = [];
    document.querySelectorAll('.scope-option').forEach(el => el.classList.remove('selected'));
}

function toggleScope(val, el) {
    if (val === 'global') {
        const isSel = deleteScope === 'global';
        if (!isSel) {
            deleteScope = 'global';
            document.querySelectorAll('.scope-option').forEach(e => e.classList.remove('selected'));
            el.classList.add('selected');
        } else {
            deleteScope = [];
            el.classList.remove('selected');
        }
    } else {
        if (deleteScope === 'global') {
            deleteScope = [];
            document.getElementById('opt-global').classList.remove('selected');
        }
        const idx = deleteScope.indexOf(val);
        if (idx > -1) {
            deleteScope.splice(idx, 1);
            el.classList.remove('selected');
        } else {
            deleteScope.push(val);
            el.classList.add('selected');
        }
    }
}

async function confirmDelete() {
    if (!selectedProduct || (!deleteScope.length && deleteScope !== 'global')) {
         alert('Пожалуйста, выберите товар и место удаления.');
         return;
    }
    if (!confirm('Вы уверены, что хотите удалить ' + selectedProduct + '?')) return;
    
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
    await fetch('/admin/delete_product', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({product: selectedProduct, scope: deleteScope})
    });
    
    alert('Удалено!');
    window.location.reload();
}
</script>
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}
</script>
<script>
const VAPID_KEY = 'BGsP3cZlbHjunitjrMxFkVhtMbs0Cf_1n0OiNE3jJDVBJqZiMQOxFG6Kw4CaRJHIFLl6npHAsAqP9p-bifiJlJI';

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    return Uint8Array.from([...rawData].map(c => c.charCodeAt(0)));
}

async function subscribePush() {
    const btn = document.getElementById('notifyBtn');
    if (!('Notification' in window) || !('serviceWorker' in navigator)) {
        alert('Ваш браузер не поддерживает уведомления');
        return;
    }
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
        btn.innerText = '🚫 Уведомления заблокированы';
        return;
    }
    try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(VAPID_KEY)
        });
        const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || "";
        await fetch('/push_subscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(sub)
        });
        btn.innerText = '✅ Уведомления включены';
        btn.style.background = '#10b981';
        btn.disabled = true;
    } catch(e) {
        console.error('Push subscribe error', e);
        btn.innerText = '❌ Ошибка подписки';
    }
}

// Авто-восстановление подписки если уже разрешены
if ('serviceWorker' in navigator && Notification.permission === 'granted') {
    navigator.serviceWorker.ready.then(reg => {
        reg.pushManager.getSubscription().then(sub => {
            if (sub) {
                const btn = document.getElementById('notifyBtn');
                if (btn) { btn.innerText = '✅ Уведомления включены'; btn.style.background = '#10b981'; btn.disabled = true; }
            }
        });
    });
}
</script>
</body>
</html>''' 
    return render_template_string(html, users=user_list, pending_finish=db_get_pending(), LOCATIONS=get_locations())

@app.route('/admin/create_user', methods=['POST'])
@require_admin
def create_user():
    username = request.form['username']
    password = request.form['password'] or secrets.token_urlsafe(8)
    db_create_user(username, generate_password_hash(password))
    return redirect('/admin')

@app.route('/admin/delete_user', methods=['POST'])
@require_admin
def delete_user():
    username = request.form['username']
    if username != 'admin':
        db_delete_user(username)
    return redirect('/admin')

@app.route('/admin/edit_products', methods=['POST'])
@require_admin
def edit_products():
    locations = request.form.getlist('locations')
    category = request.form['category']
    name = request.form['name']
    code = request.form['code']
    unit = request.form['unit']
    action = request.form['action']

    if not locations:
        return redirect('/admin')

    locs = get_locations()
    for location in locations:
        if location not in locs:
            continue
        if action == 'add':
            db_upsert_product(location, category, name, code, unit, removed=0)
        elif action == 'remove':
            db_upsert_product(location, category, name, code, unit, removed=1)

    return redirect('/admin')

@app.route('/admin/search_products')
@require_admin
def search_products():
    query = request.args.get('q', '').lower()
    results = set()
    for loc_data in get_locations().values():
        for cat, products in loc_data.items():
            for name in products:
                if query in name.lower():
                    results.add(name)
    return jsonify(list(results))

@app.route('/admin/delete_product', methods=['POST'])
@require_admin
def delete_product_endpoint():
    data = request.json
    product_name = data.get('product')
    scope = data.get('scope')

    locs = get_locations()
    targets = list(locs.keys()) if scope == 'global' else scope
    for loc in targets:
        if loc not in locs:
            continue
        for cat, products in locs[loc].items():
            if product_name in products:
                info = products[product_name]
                db_upsert_product(loc, cat, product_name, info.get('code', ''), info.get('unit', 'шт'), removed=1)

    return jsonify({'status': 'ok'})

@app.route("/admin/finish_confirm", methods=["POST"])
@require_admin
def finishconfirm():
    requestid = request.form.get("request_id")
    pending = db_get_pending()
    if requestid in pending:
        data = pending[requestid]
        operator_name = data.get('user', 'Unknown')
        timestamp = data.get('timestamp', '')

        aggregated_data = {}
        inv = db_get_inventory()
        for location, loc_data in get_locations().items():
            for cat, products in loc_data.items():
                for name, info in products.items():
                    qty = inv.get((location, name), 0)
                    if qty:
                        code = str(info.get("code", ""))
                        try:
                            qty_val = float(qty)
                        except ValueError:
                            qty_val = 0
                        if code:
                            aggregated_data[code] = aggregated_data.get(code, 0) + qty_val

        # Загружаем шаблон
        file_path = os.path.join(os.path.dirname(__file__), 'template.xlsx')
        if os.path.exists(file_path):
            import openpyxl
            wb = openpyxl.load_workbook(file_path)
            ws = wb.active
            
            # Заполняем шаблон
            import datetime
            today_str = datetime.datetime.now().strftime('%d.%m.%Y')
            
            for row in range(1, ws.max_row + 1):
                # Ищем "Дата печати" или "НА ДАТУ:" и ставим текущую
                for col in range(1, 10):
                    c_val = ws.cell(row=row, column=col).value
                    if isinstance(c_val, str):
                        if 'Дата печати' in c_val:
                            ws.cell(row=row, column=col, value=f'Дата печати: {today_str}')
                        elif 'НА ДАТУ:' in c_val.upper():
                            ws.cell(row=row, column=col, value=f'НА ДАТУ: {today_str}')

                code_raw = ws.cell(row=row, column=2).value
                if code_raw is not None:
                    code_str = str(code_raw).strip()
                    if code_str in aggregated_data and aggregated_data[code_str] > 0:
                        # Вставляем количество в Остаток фактический (Колонка G = 7)
                        ws.cell(row=row, column=7, value=aggregated_data[code_str])
        else:
            # Fallback если шаблона нет
            from openpyxl import Workbook
            wb = Workbook()
            ws = wb.active
            ws.title = "Error"
            ws.append(["Шаблон template.xlsx не найден!"])

        # сохраняем в память
        import io
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)

        db_clear_inventory()
        db_delete_pending(requestid)

        # отправляем файл пользователю
        filename = f"revision_{timestamp.replace(':', '-')}_{operator_name}.xlsx"
        from flask import send_file
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    return redirect("/admin")

@app.route('/admin/finish_cancel', methods=['POST'])
@require_admin
def finish_cancel():
    request_id = request.form['request_id']
    db_delete_pending(request_id)
    return redirect('/admin')

# ============== РЕВИЗИЯ (Для операторов и админа) ==============
@app.route('/revision')
@require_login
def revision():
    selected_location = request.args.get("location", "Склад")
    now_date = datetime.now().strftime('%d.%m.%Y')
    return render_template_string(revision_html, locations=get_locations(), inventory=db_get_inventory(), history=db_get_history(), current=selected_location, role=session.get('role', 'operator'), now_date=now_date)

@app.route('/add_api', methods=['POST'])
@require_login
def add_api():
    location = request.form['location']
    name = request.form['name']
    count = float(request.form['count'])
    timestamp = datetime.now().strftime("%d.%m %H:%M:%S")
    item = {
        'id': str(uuid.uuid4()),
        'text': f"{timestamp}: {session['username']} добавил {count}",
        'count': count,
        'user': session['username'],
        'timestamp': timestamp
    }
    db_update_inventory(location, name, count)
    db_add_history(location, name, item)
    return ('', 204)

@app.route('/delete_history_api', methods=['POST'])
@require_login
def delete_history_api():
    hist_id = request.form['id']
    result = db_delete_history_item(hist_id)
    if result is None:
        return ('Item not found', 404)
    count_to_remove, item_user, location, name = result
    if session.get('role') != 'admin' and item_user != session.get('username'):
        db_add_history(location, name, {'id': hist_id, 'text': '(restored)', 'count': count_to_remove, 'user': item_user, 'timestamp': datetime.now().strftime("%d.%m %H:%M:%S")})
        return ('Permission denied', 403)
    db_revert_inventory(location, name, count_to_remove)
    return ('', 204)

@app.route('/request_finish', methods=['POST'])
@require_login
def request_finish():
    request_id = secrets.token_urlsafe(8)
    location = request.args.get('location', 'Все')
    timestamp = datetime.now().strftime("%d.%m %H:%M:%S")
    db_add_pending(request_id, session['username'], location, timestamp)
    # Отправляем push-уведомление всем администраторам
    try:
        send_push_notification(
            title=f"🍔 Запрос на завершение ревизии",
            body=f"Оператор {session['username']} завершил ревизию ({location})"
        )
    except Exception as e:
        print(f"Push send error: {e}")
    return jsonify({'request_id': request_id})

@app.route('/push_subscribe', methods=['POST'])
@require_admin
def push_subscribe():
    sub = request.json
    if sub:
        db_add_subscription(sub)
    return jsonify({'status': 'subscribed'})

@app.route('/vapid_public_key')
def vapid_public_key():
    return jsonify({'key': VAPID_PUBLIC_KEY})

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    # Debug mode is only enabled if FLASK_DEBUG is explicitly set to 1
    debug = os.environ.get('FLASK_DEBUG') == '1'
    app.run(host="0.0.0.0", port=port, debug=debug)

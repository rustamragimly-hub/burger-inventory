from flask import Flask, request, render_template_string, send_file, jsonify, redirect, session
from threading import Lock
from openpyxl import Workbook
from werkzeug.security import generate_password_hash, check_password_hash
import io
from datetime import datetime
import secrets
import os
import uuid

app = Flask(__name__)

@app.route("/")
def index():
    return redirect("/login")


app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Данные хранилища
inventory = {}
history = {}
users = {"admin": {"password": generate_password_hash("admin123"), "role": "admin"}}
pending_finish = {}
inventory_lock = Lock()
users_lock = Lock()

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

LOCATIONS = {
    "Склад": {},
    "Кухня": {},
    "Островок": {}
}

def init_locations():
    for location in LOCATIONS:
        for category, products in GLOBAL_PRODUCTS.items():
            LOCATIONS[location][category] = dict(products)

init_locations()

# ============== АВТОРИЗАЦИЯ ==============
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with users_lock:
            if username in users and check_password_hash(users[username]['password'], password):
                session['username'] = username
                session['role'] = users[username]['role']
                return redirect('/admin' if users[username]['role'] == 'admin' else '/revision')
            else:
                return render_template_string(login_html, error="❌ Неверный логин или пароль")
    return render_template_string(login_html, now=datetime.now().strftime("%d.%m %H:%M"))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

login_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Вход</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    --card-bg: rgba(255, 255, 255, 0.95);
    --text-color: #1e293b;
    --error-bg: #fee2e2;
    --error-text: #991b1b;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-gradient);
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 20px;
}
.login-box {
    background: var(--card-bg);
    padding: 40px 30px;
    border-radius: 24px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    max-width: 400px;
    width: 100%;
    backdrop-filter: blur(10px);
    animation: fadeIn 0.5s ease-out;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
h1 {
    text-align: center;
    color: var(--primary);
    margin-bottom: 30px;
    font-weight: 600;
    font-size: 28px;
}
.form-group { margin-bottom: 20px; }
.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: #475569;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.form-group input {
    width: 100%;
    padding: 14px 16px;
    border: 2px solid #e2e8f0;
    border-radius: 12px;
    font-size: 16px;
    transition: all 0.3s ease;
    background: #f8fafc;
}
.form-group input:focus {
    outline: none;
    border-color: var(--primary);
    background: white;
    box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
}
.btn {
    width: 100%;
    background: var(--primary);
    color: white;
    border: none;
    padding: 16px;
    border-radius: 12px;
    font-weight: 600;
    cursor: pointer;
    font-size: 16px;
    transition: transform 0.2s, box-shadow 0.2s;
    margin-top: 10px;
}
.btn:active { transform: scale(0.98); }
.error {
    color: var(--error-text);
    background: var(--error-bg);
    padding: 12px;
    border-radius: 12px;
    margin-bottom: 20px;
    text-align: center;
    font-size: 14px;
    border: 1px solid #fecaca;
}
</style>
</head>
<body>
<div class="login-box">
<h1>🔐 Вход</h1>
{% if error %}<div class="error">{{error}}</div>{% endif %}
<form method="post">
<div class="form-group">
  <label>Логин</label>
  <input type="text" name="username" required autocomplete="username">
</div>
<div class="form-group">
  <label>Пароль</label>
  <input type="password" name="password" required autocomplete="current-password">
</div>
<button class="btn" type="submit">Войти</button>
</form>
<div style="text-align:center;color:#999;font-size:12px;margin-top:20px;">Версия: {{ now }}</div>
</div>
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
    with users_lock:
        user_list = [(u, users[u]['role']) for u in users]
    html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Панель Администратора</title>
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
            <input class="form-input" type="text" name="username" placeholder="Логин" required>
            <input class="form-input" type="text" name="password" placeholder="Пароль (опционально)">
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
            <input type="hidden" name="username" value="{{user}}">
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
            <div class="scope-option location-opt" onclick="toggleScope('{{loc}}', this)">
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
                    <input type="hidden" name="request_id" value="{{req_id}}">
                    <button class="btn btn-primary" style="width:100%">Подтвердить</button>
                </form>
                 <form method="post" action="/admin/finish_cancel" style="width:100%">
                    <input type="hidden" name="request_id" value="{{req_id}}">
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
    
    await fetch('/admin/delete_product', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({product: selectedProduct, scope: deleteScope})
    });
    
    alert('Удалено!');
    window.location.reload();
}
</script>
</body>
</html>''' 
    return render_template_string(html, users=user_list, pending_finish=pending_finish, LOCATIONS=LOCATIONS)

@app.route('/admin/create_user', methods=['POST'])
@require_admin
def create_user():
    username = request.form['username']
    password = request.form['password'] or secrets.token_urlsafe(8)
    with users_lock:
        if username not in users:
            users[username] = {'password': generate_password_hash(password), 'role': 'operator'}
    return redirect('/admin')

@app.route('/admin/delete_user', methods=['POST'])
@require_admin
def delete_user():
    username = request.form['username']
    with users_lock:
        if username in users and username != 'admin':
            del users[username]
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
    
    # Если ничего не выбрано, ничего не делаем (или можно добавить default)
    if not locations:
        return redirect('/admin')

    for location in locations:
        # Защита если вдруг локация кривая
        if location not in LOCATIONS:
            continue
            
        if action == 'add':
            if category not in LOCATIONS[location]:
                LOCATIONS[location][category] = {}
            LOCATIONS[location][category][name] = {'code': code, 'unit': unit}
        elif action == 'remove':
            if category in LOCATIONS[location] and name in LOCATIONS[location][category]:
                del LOCATIONS[location][category][name]
                # Удаляем категорию если пустая
                if not LOCATIONS[location][category]:
                    del LOCATIONS[location][category]
                    
    return redirect('/admin')

@app.route('/admin/search_products')
@require_admin
def search_products():
    query = request.args.get('q', '').lower()
    results = set()
    for loc_data in LOCATIONS.values():
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
    scope = data.get('scope') # 'global' or list of locations
    
    if scope == 'global':
        # Remove from GLOBAL_PRODUCTS
        for cat in list(GLOBAL_PRODUCTS.keys()):
            if product_name in GLOBAL_PRODUCTS[cat]:
                del GLOBAL_PRODUCTS[cat][product_name]
        # Remove from all locations
        for loc in LOCATIONS:
            for cat in list(LOCATIONS[loc].keys()):
                if product_name in LOCATIONS[loc][cat]:
                    del LOCATIONS[loc][cat][product_name]
    else:
        # Remove from specific locations
        for loc in scope:
            if loc in LOCATIONS:
                for cat in list(LOCATIONS[loc].keys()):
                    if product_name in LOCATIONS[loc][cat]:
                        del LOCATIONS[loc][cat][product_name]
                        
    return jsonify({'status': 'ok'})

@app.route("/admin/finish_confirm", methods=["POST"])
@require_admin
def finishconfirm():
    requestid = request.form.get("request_id")
    if requestid in pending_finish:
        data = pending_finish[requestid]
        operator_name = data.get('user', 'Unknown')
        timestamp = data.get('timestamp', '')

        # Сбор данных и агрегация
        aggregated_data = {} # code -> qty
        with inventory_lock:
            for location in LOCATIONS:
                for cat, products in LOCATIONS[location].items():
                    for name, info in products.items():
                        qty = inventory.get((location, name), 0)
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

        # очищаем состояние ревизии
        inventory.clear()
        history.clear()
        if requestid in pending_finish:
            del pending_finish[requestid]

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
    if request_id in pending_finish:
        del pending_finish[request_id]
    return redirect('/admin')

# ============== РЕВИЗИЯ (Для операторов и админа) ==============
@app.route('/revision')
@require_login
def revision():
    selected_location = request.args.get("location", "Склад")
    with inventory_lock:
        inv = dict(inventory)
        hist = dict(history)
    
    now_date = datetime.now().strftime('%d.%m.%Y')
    return render_template_string(revision_html, locations=LOCATIONS, inventory=inv, history=hist, current=selected_location, role=session.get('role', 'operator'), now_date=now_date)

revision_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Ревизия</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-light: #818cf8;
    --bg-body: #f1f5f9;
    --card-bg: #ffffff;
    --text-main: #1e293b;
    --text-muted: #64748b;
    --success: #10b981;
    --danger: #ef4444;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-body);
    margin: 0;
    padding: 0;
    color: var(--text-main);
    padding-bottom: 80px; /* Space for bottom actions */
}
header {
    background: var(--card-bg);
    padding: 15px 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
header h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 700;
    background: linear-gradient(135deg, var(--primary), var(--primary-light));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.header-actions { display: flex; gap: 10px; }
.btn-icon {
    background: #f8fafc;
    border: none;
    padding: 8px 12px;
    border-radius: 8px;
    color: var(--text-main);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
}
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 15px 20px;
    gap: 12px;
    background: var(--bg-body);
    scrollbar-width: none;
}
.tabs::-webkit-scrollbar { display: none; }
.tab {
    padding: 8px 20px;
    background: white;
    border-radius: 50px;
    font-weight: 600;
    color: var(--text-muted);
    text-decoration: none;
    white-space: nowrap;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    transition: all 0.2s;
    font-size: 14px;
}
.tab.active {
    background: var(--primary);
    color: white;
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
}
.container { padding: 0 20px; }
.search-box {
    position: sticky;
    top: 60px;
    z-index: 90;
    background: var(--bg-body);
    padding: 10px 0;
}
.search-box input {
    width: 100%;
    padding: 12px 16px;
    border: none;
    border-radius: 12px;
    background: white;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    font-size: 16px;
    font-family: inherit;
}
.product-group { margin-bottom: 25px; }
.product-group h3 {
    margin: 15px 0 10px;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    font-weight: 700;
}
.product-item {
    background: var(--card-bg);
    padding: 16px;
    border-radius: 12px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    cursor: pointer;
    transition: transform 0.1s;
}
.product-item:active { transform: scale(0.98); }
.p-name { font-weight: 500; font-size: 15px; }
.p-meta { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
.badge {
    background: var(--primary);
    color: white;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 600;
    min-width: 30px;
    text-align: center;
}
/* Modal & Calc */
.modal {
    display: none;
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(4px);
    z-index: 1000;
    align-items: flex-end; /* Sheet style on mobile */
}
.modal.active { display: flex; animation: fadeIn 0.2s; }
.modal-content {
    background: white;
    width: 100%;
    border-radius: 24px 24px 0 0;
    padding: 24px;
    box-shadow: 0 -10px 40px rgba(0,0,0,0.2);
    animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
@keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
.calc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.calc-title { font-size: 18px; font-weight: 700; color: var(--text-main); max-width: 80%; }
.calc-display {
    width: 100%;
    font-size: 32px;
    padding: 10px;
    text-align: right;
    border: none;
    border-bottom: 2px solid #e2e8f0;
    margin-bottom: 20px;
    font-family: 'Outfit', monospace;
    color: var(--primary);
    background: transparent;
}
.calc-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.c-btn {
    padding: 15px;
    border-radius: 12px;
    border: none;
    font-size: 20px;
    font-weight: 500;
    background: #f1f5f9;
    color: var(--text-main);
    touch-action: manipulation;
}
.c-btn:active { background: #e2e8f0; }
.op-btn { background: #e0e7ff; color: var(--primary); }
.submit-btn {
    grid-column: span 2;
    background: var(--primary);
    color: white;
    font-weight: 600;
}
.total-row {
    margin-top: 15px;
    text-align: center;
    font-size: 16px;
    color: var(--text-muted);
}
.highlight { color: var(--primary); font-weight: 700; }
.history-log {
    margin-top: 20px;
    background: #f8fafc;
    padding: 10px;
    border-radius: 8px;
    font-size: 11px;
    color: var(--text-muted);
    max-height: 100px;
    overflow-y: auto;
}
.history-item { border-bottom: 1px solid #e2e8f0; padding: 4px 0; }
.history-item:last-child { border-bottom: none; }
/* Added Values List */
.values-list {
    margin: 10px 0;
    max-height: 100px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background: #f8fafc;
    display: none;
}
.value-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid #e2e8f0;
    font-size: 14px;
}
.value-item:last-child { border-bottom: none; }
.del-val-btn {
    color: var(--danger);
    background: none;
    border: none;
    cursor: pointer;
    font-size: 18px;
    padding: 0 8px;
    line-height: 1;
}

.finish-btn {
    position: fixed;
    bottom: 20px;
    left: 20px;
    right: 20px;
    background: var(--text-main);
    color: white;
    border: none;
    padding: 16px;
    border-radius: 16px;
    font-size: 16px;
    font-weight: 600;
    box-shadow: 0 10px 20px rgba(0,0,0,0.1);
    z-index: 90;
}
</style>
</head>
<body>
<header>
    <h1>Инвентаризация</h1>
    <div class="header-actions">
        {% if role == 'admin' %}
        <a href="/admin"><button class="btn-icon">⚙️ Админ</button></a>
        {% endif %}
        <a href="/logout"><button class="btn-icon">Выход</button></a>
    </div>
</header>

<div class="tabs">
    <a href="/revision?location=Склад" class="tab {% if 'Склад' == current %}active{% endif %}">Склад</a>
    <a href="/revision?location=Кухня" class="tab {% if 'Кухня' == current %}active{% endif %}">Кухня</a>
    <a href="/revision?location=Островок" class="tab {% if 'Островок' == current %}active{% endif %}">Островок</a>
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
      <div class="product-item" data-name="{{name | lower}}" data-history='{{ hist_list | tojson }}' onclick="openCalc('{{current}}','{{name}}','{{data.unit}}', this)">
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

<button class="finish-btn" onclick="requestFinish()">Завершить ревизию</button>

<!-- Calculator Modal -->
<div class="modal" id="calcModal" onclick="if(event.target===this)closeCalc()">
<div class="modal-content">
    <div class="calc-header">
        <div class="calc-title" id="calcTitle"></div>
        <button class="btn-icon" onclick="closeCalc()">✕</button>
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
        <button class="c-btn op-btn" style="font-size:16px" onclick="addToTotal()">Внести</button>
        <button class="c-btn submit-btn" onclick="saveResult()">СОХРАНИТЬ</button>
    </div>
    <div id="addedValuesList" class="values-list"></div>
    <div class="total-row">Итого: <span id="total" class="highlight">0</span> <span id="unit"></span></div>
    <div style="margin-top:15px;border-top:1px solid #eee;padding-top:10px;">
        <div style="font-size:12px;color:#999;margin-bottom:5px;">История операций (текущая сессия):</div>
        <div id="calcHistory" class="history-log"></div>
    </div>
</div>
</div>

<!-- Confirm Modal -->
<div class="modal" id="confirmModal">
<div class="modal-content" style="text-align:center;border-radius:24px;">
    <h2 style="color:var(--primary);">Запрос отправлен</h2>
    <p style="color:var(--text-muted);margin-bottom:20px;">Ожидание подтверждения администратором...</p>
    <button class="finish-btn" style="position:static;background:#cbd5e1;color:#333;" onclick="cancelRequest()">Отмена</button>
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
    if(item.style.display==='flex') item.closest('.product-group').style.display='block';
  });
  // Hide empty groups
  document.querySelectorAll('.product-group').forEach(group => {
     const visibleItems = Array.from(group.querySelectorAll('.product-item')).filter(i => i.style.display !== 'none');
     group.style.display = visibleItems.length > 0 ? 'block' : 'none';
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
  
  // History
  const history = JSON.parse(el.getAttribute('data-history') || '[]');
  renderHistory(history);
  document.getElementById('calcModal').classList.add('active');
}

function renderHistory(history) {
    const historyContainer = document.getElementById('calcHistory');
    if(history.length > 0) {
        historyContainer.innerHTML = history.map(h => {
             // Handle both old string format and new dict format
             let text = '';
             let id = null;
             if (typeof h === 'string') {
                 text = h;
             } else {
                 text = h.text;
                 id = h.id;
             }
             
             let delBtn = '';
             if (id) {
                 delBtn = `<button class="del-val-btn" onclick="deleteHistoryItem('${id}', '${loc}', '${prod}')" title="Удалить запись">×</button>`;
             }
             
             return `<div class="history-item" style="display:flex;justify-content:space-between;">
                <span>${text}</span>
                ${delBtn}
             </div>`;
        }).reverse().join('');
        historyContainer.style.display = 'block';
    } else {
        historyContainer.innerHTML = 'История пуста';
        historyContainer.style.display = 'block';
    }
}

async function deleteHistoryItem(id, location, name) {
    if(!confirm('Удалить эту запись из истории? Это изменит текущий остаток.')) return;
    
    const fd = new FormData();
    fd.append('id', id);
    fd.append('location', location);
    fd.append('name', name);
    
    const res = await fetch('/delete_history_api', {method:'POST', body:fd});
    if (res.ok) {
        window.location.reload();
    } else {
        alert('Ошибка при удалении');
    }
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
    if(!isNaN(n) && n !== 0){
        addedValues.push(n);
        renderValuesList();
    }
    val='0';
    document.getElementById('calcDisplay').value='0';
}

function renderValuesList() {
    const list = document.getElementById('addedValuesList');
    if (addedValues.length === 0) {
        list.style.display = 'none';
        list.innerHTML = '';
        total = 0;
    } else {
        list.style.display = 'block';
        list.innerHTML = addedValues.map((v, i) => `
            <div class="value-item">
                <span>${v}</span>
                <button class="del-val-btn" onclick="removeValue(${i})">×</button>
            </div>
        `).join('');
        total = addedValues.reduce((a, b) => a + b, 0);
    }
    // Round total to avoid float errors
    total = Math.round(total * 1000) / 1000;
    document.getElementById('total').innerText = total;
}

function removeValue(i) {
    addedValues.splice(i, 1);
    renderValuesList();
}

async function saveResult(){
  // If user has put things in the list, use that total.
  // We ignore 'val' if addedValues has items to prevent double adding if they forgot to click '+' on the last one, 
  // OR we could try to be smart. Standard calc behavior: clear implicit buffer?
  // Let's assume if addedValues > 0, the specific intention was to sum those values.
  
  let n = 0;
  if (addedValues.length > 0) {
      n = total;
  } else {
      n = parseFloat(val);
      if (isNaN(n)) n = 0;
  }
  
  if(isNaN(n)||n<=0){alert('Пожалуйста, введите корректное число');return;}
  const fd=new FormData();fd.append('location',loc);fd.append('name',prod);fd.append('count',n);
  await fetch('/add_api',{method:'POST',body:fd});
  closeCalc();window.location.reload();
}

async function requestFinish(){
  const resp = await fetch('/request_finish?location=' + encodeURIComponent(loc||'Все'), {method:'POST'});
  document.getElementById('confirmModal').classList.add('active');
}

function cancelRequest(){
  document.getElementById('confirmModal').classList.remove('active');
  // Logic to actually cancel on server could be added here
}
</script>
</body>
</html>'''

@app.route('/add_api', methods=['POST'])
@require_login
def add_api():
    location = request.form['location']
    name = request.form['name']
    count = float(request.form['count'])
    timestamp = datetime.now().strftime("%d.%m %H:%M:%S")
    key = (location, name)
    key = (location, name)
    msg = f"{timestamp}: {session['username']} добавил {count}"
    item = {
        'id': str(uuid.uuid4()),
        'text': msg,
        'count': count,
        'user': session['username'],
        'timestamp': timestamp
    }
    with inventory_lock:
        inventory[key] = inventory.get(key, 0) + count
        history.setdefault(key, []).append(item)
    return ('', 204)

@app.route('/delete_history_api', methods=['POST'])
@require_login
def delete_history_api():
    hist_id = request.form['id']
    location = request.form['location']
    name = request.form['name']
    key = (location, name)
    
    with inventory_lock:
        if key in history:
            # Find item
            items = history[key]
            for i, item in enumerate(items):
                # Check if item is dict (new format) and matches ID
                if isinstance(item, dict) and item.get('id') == hist_id:
                    # Revert inventory count
                    count_to_remove = item.get('count', 0)
                    inventory[key] = inventory.get(key, 0) - count_to_remove
                    
                    # Remove from history
                    items.pop(i)
                    return ('', 204)
                    
    return ('Item not found', 404)

@app.route('/request_finish', methods=['POST'])
@require_login
def request_finish():
    request_id = secrets.token_urlsafe(8)
    location = request.args.get('location', 'Все')
    pending_finish[request_id] = {
        'user': session['username'],
        'location': location,
        'timestamp': datetime.now().strftime("%d.%m %H:%M:%S")
    }
    return jsonify({'request_id': request_id})

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host="0.0.0.0", port=port, debug=debug)

"""
Spurt — мульти-тенантная система инвентаризации.
Фаза 1: Аутентификация и регистрация компаний.
"""
from flask import (
    Flask, request, render_template_string, redirect, url_for, flash, jsonify,
    send_file, abort,
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required,
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
import secrets
import os
import re
import csv
import io
import click

from config import Config
from models import (
    db, Organization, User, Location, OwnerUser, LoginAttempt,
    Category, Product, ProductNorm, Revision, RevisionItem,
)

# ============== ИНИЦИАЛИЗАЦИЯ ==============
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите для доступа.'


# ============== ОБЁРТКИ ДЛЯ FLASK-LOGIN ==============
class AuthUser(UserMixin):
    """Обёртка над User или OwnerUser для flask-login с префиксом типа."""

    def __init__(self, record, user_type):
        self.record = record
        self.user_type = user_type  # 'user' или 'owner'

    def get_id(self):
        prefix = 'u' if self.user_type == 'user' else 'o'
        return f"{prefix}:{self.record.id}"

    # Удобный доступ к полям
    @property
    def username(self):
        if self.user_type == 'user':
            return self.record.username
        return self.record.email

    @property
    def role(self):
        if self.user_type == 'user':
            return self.record.role
        return 'owner'

    @property
    def organization(self):
        if self.user_type == 'user':
            return self.record.organization
        return None

    @property
    def user(self):
        """Актуальная запись User (None для владельцев)."""
        return self.record if self.user_type == 'user' else None

    @property
    def raw_id(self):
        return self.record.id


@login_manager.user_loader
def load_user(uid):
    try:
        prefix, raw_id = uid.split(':', 1)
        rid = int(raw_id)
    except (ValueError, AttributeError):
        return None

    if prefix == 'u':
        u = db.session.get(User, rid)
        return AuthUser(u, 'user') if u else None
    if prefix == 'o':
        o = db.session.get(OwnerUser, rid)
        return AuthUser(o, 'owner') if o else None
    return None


# ============== HELPERS ==============
def trial_days_left(org):
    if not org or not org.trial_ends_at:
        return 0
    delta = org.trial_ends_at - datetime.utcnow()
    return max(0, delta.days)


def count_recent_failed_attempts(ip):
    """Считаем неудачные попытки с этого IP за последние LOGIN_LOCKOUT_MINUTES минут."""
    cutoff = datetime.utcnow() - timedelta(minutes=Config.LOGIN_LOCKOUT_MINUTES)
    return LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,  # noqa: E712
        LoginAttempt.attempted_at >= cutoff,
    ).count()


def log_attempt(ip, username, success):
    try:
        attempt = LoginAttempt(ip_address=ip, username=username, success=success)
        db.session.add(attempt)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ============== ROOT ==============
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.user_type == 'user' and current_user.role == 'admin':
            return redirect('/admin')
        if current_user.user_type == 'user':
            return redirect('/revision')
    return redirect('/login')


# ============== РЕГИСТРАЦИЯ ==============
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        company = (request.form.get('company') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        password2 = request.form.get('password2') or ''
        terms = request.form.get('terms')

        if not (company and email and username and password):
            error = 'Заполните все поля.'
        elif len(password) < 6:
            error = 'Пароль должен быть не короче 6 символов.'
        elif password != password2:
            error = 'Пароли не совпадают.'
        elif not terms:
            error = 'Необходимо согласиться с условиями использования.'
        elif Organization.query.filter_by(owner_email=email).first():
            error = 'Компания с таким email уже зарегистрирована.'

        if error is None:
            try:
                token = secrets.token_urlsafe(32)
                org = Organization(
                    name=company,
                    owner_email=email,
                    email_verified=False,
                    email_verify_token=token,
                    plan='trial',
                    trial_ends_at=datetime.utcnow() + timedelta(days=Config.TRIAL_DAYS),
                )
                db.session.add(org)
                db.session.flush()

                admin = User(
                    org_id=org.id,
                    username=username,
                    email=email,
                    role='admin',
                )
                admin.set_password(password)
                db.session.add(admin)

                for order, loc_name in enumerate(('Склад', 'Кухня', 'Островок')):
                    db.session.add(Location(org_id=org.id, name=loc_name, sort_order=order))

                db.session.commit()

                # TODO: отправлять email в продакшне
                return redirect(url_for('register_success', token=token))
            except Exception as e:
                db.session.rollback()
                error = f'Ошибка регистрации: {e}'

    return render_template_string(register_html, error=error)


@app.route('/register/success')
def register_success():
    token = request.args.get('token', '')
    verify_url = url_for('verify_email', token=token) if token else None
    return render_template_string(register_success_html, verify_url=verify_url)


@app.route('/verify/<token>')
def verify_email(token):
    org = Organization.query.filter_by(email_verify_token=token).first()
    if not org:
        return render_template_string(
            message_html,
            title='Ссылка недействительна',
            text='Токен подтверждения не найден или уже использован.',
        ), 404

    org.email_verified = True
    org.email_verify_token = None
    db.session.commit()

    admin = User.query.filter_by(org_id=org.id, role='admin').first()
    if admin:
        login_user(AuthUser(admin, 'user'))
        admin.last_login_at = datetime.utcnow()
        db.session.commit()
        return redirect('/admin')
    return redirect('/login')


# ============== ЛОГИН / ЛОГАУТ ==============
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    ip = request.remote_addr or 'unknown'

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # Защита от брутфорса
        if count_recent_failed_attempts(ip) >= Config.MAX_LOGIN_ATTEMPTS:
            error = (
                f'Слишком много неудачных попыток. '
                f'Попробуйте через {Config.LOGIN_LOCKOUT_MINUTES} минут.'
            )
            return render_template_string(
                login_html, error=error,
                now=datetime.now().strftime('%d.%m %H:%M'),
            )

        org = Organization.query.filter_by(owner_email=email).first()
        user = None
        if org:
            user = User.query.filter_by(org_id=org.id, username=username).first()

        if not user or not user.check_password(password):
            log_attempt(ip, username, False)
            error = 'Неверный email компании, логин или пароль.'
        elif org.is_blocked:
            log_attempt(ip, username, False)
            error = 'Компания заблокирована. Обратитесь в поддержку.'
        elif not org.email_verified:
            log_attempt(ip, username, False)
            error = 'Email компании не подтверждён. Проверьте почту.'
        else:
            log_attempt(ip, username, True)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            login_user(AuthUser(user, 'user'))
            if user.role == 'admin':
                return redirect('/admin')
            return redirect('/revision')

    return render_template_string(
        login_html, error=error,
        now=datetime.now().strftime('%d.%m %H:%M'),
    )


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


# ============== АДМИН: ХЕЛПЕРЫ ==============
def _current_org():
    """Возвращает Organization текущего залогиненного пользователя (или None)."""
    if not current_user.is_authenticated:
        return None
    if current_user.user_type != 'user':
        return None
    u = current_user.user
    if not u:
        return None
    return db.session.get(Organization, u.org_id)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect('/login')
        if current_user.user_type != 'user':
            return redirect('/login')
        u = current_user.user
        if not u or u.role != 'admin':
            return redirect('/login')
        return fn(*args, **kwargs)
    return wrapper


def login_required_user(fn):
    """Доступ для любого User (админ или оператор), но не OwnerUser."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect('/login')
        if current_user.user_type != 'user':
            return redirect('/login')
        if not current_user.user:
            return redirect('/login')
        return fn(*args, **kwargs)
    return wrapper


def _get_or_create_active_revision(org_id, location_id, user_id):
    """Возвращает активную (in_progress) ревизию для (org, location) или создаёт."""
    rev = Revision.query.filter_by(
        org_id=org_id, location_id=location_id, status='in_progress'
    ).first()
    if not rev:
        rev = Revision(
            org_id=org_id, user_id=user_id,
            location_id=location_id, status='in_progress',
        )
        db.session.add(rev)
        db.session.flush()
    return rev


def _generate_product_code(org_id):
    """Сгенерировать уникальный код товара формата P{org_id}-{NNN}."""
    prefix = f'P{org_id}-'
    max_num = 0
    existing = Product.query.filter_by(org_id=org_id).all()
    pat = re.compile(r'^P' + str(org_id) + r'-(\d+)$')
    for p in existing:
        if p.code:
            m = pat.match(p.code)
            if m:
                try:
                    n = int(m.group(1))
                    if n > max_num:
                        max_num = n
                except ValueError:
                    pass
    next_num = max_num + 1
    return f'{prefix}{next_num:03d}'


# ============== АДМИН: ПАНЕЛЬ ==============
@app.route('/admin')
@admin_required
def admin_panel():
    org = _current_org()
    locations = Location.query.filter_by(org_id=org.id).order_by(Location.sort_order, Location.name).all()
    categories = Category.query.filter_by(org_id=org.id).order_by(Category.sort_order, Category.name).all()
    products = Product.query.filter_by(org_id=org.id).order_by(Product.name).all()
    users = User.query.filter_by(org_id=org.id).order_by(User.created_at).all()

    # Нормы: {(product_id, location_id): qty}
    norms_map = {}
    if products and locations:
        product_ids = [p.id for p in products]
        for n in ProductNorm.query.filter(ProductNorm.product_id.in_(product_ids)).all():
            norms_map[(n.product_id, n.location_id)] = n.norm_qty

    # Группировка товаров по категориям
    cat_map = {c.id: c for c in categories}
    grouped = {}
    for p in products:
        key = p.category_id
        grouped.setdefault(key, []).append(p)

    user_limit_reached = (
        org.plan == 'free' and len(users) >= Config.FREE_MAX_USERS
    )

    # Новый сгенерированный пароль (однократный показ)
    new_user_pwd = request.args.get('new_pwd')
    new_user_name = request.args.get('new_user')

    # Ревизии: запросы (pending) и история (completed)
    pending_revs = Revision.query.filter_by(org_id=org.id, status='pending').order_by(Revision.created_at.desc()).all()
    completed_revs = Revision.query.filter_by(org_id=org.id, status='completed').order_by(Revision.finished_at.desc()).limit(50).all()
    loc_map = {l.id: l for l in locations}
    user_map = {u.id: u for u in users}

    def _rev_info(r):
        loc = loc_map.get(r.location_id)
        u = user_map.get(r.user_id)
        cnt = RevisionItem.query.filter_by(revision_id=r.id).count()
        return {
            'id': r.id,
            'location': loc.name if loc else '—',
            'user': u.username if u else '—',
            'created_at': r.created_at.strftime('%d.%m.%Y %H:%M') if r.created_at else '',
            'finished_at': r.finished_at.strftime('%d.%m.%Y %H:%M') if r.finished_at else '',
            'items_count': cnt,
        }

    pending_list = [_rev_info(r) for r in pending_revs]
    completed_list = [_rev_info(r) for r in completed_revs]

    return render_template_string(
        admin_html,
        org=org,
        username=current_user.username,
        locations=locations,
        categories=categories,
        products=products,
        grouped=grouped,
        cat_map=cat_map,
        users=users,
        current_user_id=current_user.raw_id,
        norms_map=norms_map,
        days_left=trial_days_left(org),
        user_limit_reached=user_limit_reached,
        free_max_users=Config.FREE_MAX_USERS,
        new_user_pwd=new_user_pwd,
        new_user_name=new_user_name,
        pending_revs=pending_list,
        completed_revs=completed_list,
    )


# ============== АДМИН: ЛОКАЦИИ ==============
@app.route('/admin/locations/add', methods=['POST'])
@admin_required
def admin_add_location():
    org = _current_org()
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Введите название локации.', 'error')
        return redirect('/admin#tab-locations')
    if Location.query.filter_by(org_id=org.id, name=name).first():
        flash('Локация с таким именем уже существует.', 'error')
        return redirect('/admin#tab-locations')
    try:
        max_order = db.session.query(db.func.max(Location.sort_order)).filter_by(org_id=org.id).scalar() or 0
        db.session.add(Location(org_id=org.id, name=name, sort_order=max_order + 1))
        db.session.commit()
        flash(f'Локация «{name}» добавлена.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-locations')


@app.route('/admin/locations/delete/<int:loc_id>', methods=['POST'])
@admin_required
def admin_delete_location(loc_id):
    org = _current_org()
    loc = Location.query.filter_by(id=loc_id, org_id=org.id).first()
    if not loc:
        flash('Локация не найдена.', 'error')
        return redirect('/admin#tab-locations')
    try:
        # Удалить нормы, привязанные к локации
        ProductNorm.query.filter_by(location_id=loc.id).delete(synchronize_session=False)
        # Удалить элементы ревизий на этой локации
        from models import RevisionItem, Revision
        RevisionItem.query.filter_by(location_id=loc.id).delete(synchronize_session=False)
        Revision.query.filter_by(location_id=loc.id).update({'location_id': None}, synchronize_session=False)
        db.session.delete(loc)
        db.session.commit()
        flash('Локация удалена.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Не удалось удалить локацию: {e}', 'error')
    return redirect('/admin#tab-locations')


# ============== АДМИН: КАТЕГОРИИ ==============
@app.route('/admin/categories/add', methods=['POST'])
@admin_required
def admin_add_category():
    org = _current_org()
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Введите название категории.', 'error')
        return redirect('/admin#tab-categories')
    if Category.query.filter_by(org_id=org.id, name=name).first():
        flash('Категория уже существует.', 'error')
        return redirect('/admin#tab-categories')
    try:
        max_order = db.session.query(db.func.max(Category.sort_order)).filter_by(org_id=org.id).scalar() or 0
        db.session.add(Category(org_id=org.id, name=name, sort_order=max_order + 1))
        db.session.commit()
        flash(f'Категория «{name}» добавлена.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-categories')


@app.route('/admin/categories/delete/<int:cat_id>', methods=['POST'])
@admin_required
def admin_delete_category(cat_id):
    org = _current_org()
    cat = Category.query.filter_by(id=cat_id, org_id=org.id).first()
    if not cat:
        flash('Категория не найдена.', 'error')
        return redirect('/admin#tab-categories')
    has_products = Product.query.filter_by(org_id=org.id, category_id=cat.id).count()
    if has_products:
        flash(f'Нельзя удалить категорию: в ней есть товары ({has_products}). Сначала удалите товары.', 'error')
        return redirect('/admin#tab-categories')
    try:
        db.session.delete(cat)
        db.session.commit()
        flash('Категория удалена.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-categories')


# ============== АДМИН: ТОВАРЫ ==============
@app.route('/admin/products/add', methods=['POST'])
@admin_required
def admin_add_product():
    org = _current_org()
    name = (request.form.get('name') or '').strip()
    category_id = request.form.get('category_id') or ''
    new_category = (request.form.get('new_category') or '').strip()
    unit = (request.form.get('unit') or 'шт').strip() or 'шт'
    code = (request.form.get('code') or '').strip()

    if not name:
        flash('Введите название товара.', 'error')
        return redirect('/admin#tab-products')

    try:
        # Создать категорию inline, если нужно
        cat_id = None
        if new_category:
            existing = Category.query.filter_by(org_id=org.id, name=new_category).first()
            if existing:
                cat_id = existing.id
            else:
                max_order = db.session.query(db.func.max(Category.sort_order)).filter_by(org_id=org.id).scalar() or 0
                c = Category(org_id=org.id, name=new_category, sort_order=max_order + 1)
                db.session.add(c)
                db.session.flush()
                cat_id = c.id
        elif category_id:
            c = Category.query.filter_by(id=int(category_id), org_id=org.id).first()
            if c:
                cat_id = c.id

        if not code:
            code = _generate_product_code(org.id)
        else:
            if Product.query.filter_by(org_id=org.id, code=code).first():
                flash(f'Товар с кодом «{code}» уже существует.', 'error')
                db.session.rollback()
                return redirect('/admin#tab-products')

        p = Product(org_id=org.id, name=name, category_id=cat_id, unit=unit, code=code)
        db.session.add(p)
        db.session.commit()
        flash(f'Товар «{name}» добавлен (код {code}).', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-products')


@app.route('/admin/products/edit/<int:pid>', methods=['POST'])
@admin_required
def admin_edit_product(pid):
    org = _current_org()
    p = Product.query.filter_by(id=pid, org_id=org.id).first()
    if not p:
        flash('Товар не найден.', 'error')
        return redirect('/admin#tab-products')
    name = (request.form.get('name') or '').strip()
    category_id = request.form.get('category_id') or ''
    unit = (request.form.get('unit') or 'шт').strip() or 'шт'
    code = (request.form.get('code') or '').strip()
    if not name:
        flash('Название не может быть пустым.', 'error')
        return redirect('/admin#tab-products')
    try:
        p.name = name
        p.unit = unit
        if category_id:
            c = Category.query.filter_by(id=int(category_id), org_id=org.id).first()
            p.category_id = c.id if c else None
        else:
            p.category_id = None
        if code and code != p.code:
            dup = Product.query.filter(
                Product.org_id == org.id, Product.code == code, Product.id != p.id
            ).first()
            if dup:
                flash('Код уже используется другим товаром.', 'error')
                db.session.rollback()
                return redirect('/admin#tab-products')
            p.code = code
        elif not code:
            p.code = _generate_product_code(org.id) if not p.code else p.code
        db.session.commit()
        flash('Товар обновлён.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-products')


@app.route('/admin/products/delete/<int:pid>', methods=['POST'])
@admin_required
def admin_delete_product(pid):
    org = _current_org()
    p = Product.query.filter_by(id=pid, org_id=org.id).first()
    if not p:
        flash('Товар не найден.', 'error')
        return redirect('/admin#tab-products')
    try:
        from models import RevisionItem
        RevisionItem.query.filter_by(product_id=p.id).delete(synchronize_session=False)
        ProductNorm.query.filter_by(product_id=p.id).delete(synchronize_session=False)
        db.session.delete(p)
        db.session.commit()
        flash('Товар удалён.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-products')


# ============== АДМИН: ПОЛЬЗОВАТЕЛИ ==============
@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    org = _current_org()
    count = User.query.filter_by(org_id=org.id).count()
    if org.plan == 'free' and count >= Config.FREE_MAX_USERS:
        flash(f'Лимит тарифа FREE: максимум {Config.FREE_MAX_USERS} пользователей. Обновите тариф.', 'error')
        return redirect('/admin#tab-users')

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    email = (request.form.get('email') or '').strip().lower() or None
    if not username:
        flash('Введите логин.', 'error')
        return redirect('/admin#tab-users')
    if User.query.filter_by(org_id=org.id, username=username).first():
        flash('Пользователь с таким логином уже существует.', 'error')
        return redirect('/admin#tab-users')

    generated = None
    if not password:
        password = secrets.token_urlsafe(8)
        generated = password

    try:
        u = User(org_id=org.id, username=username, email=email, role='operator')
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        if generated:
            flash(f'Оператор «{username}» создан.', 'success')
            return redirect(url_for('admin_panel', new_user=username, new_pwd=generated) + '#tab-users')
        flash(f'Оператор «{username}» создан.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-users')


@app.route('/admin/users/delete/<int:uid>', methods=['POST'])
@admin_required
def admin_delete_user(uid):
    org = _current_org()
    if uid == current_user.raw_id:
        flash('Нельзя удалить самого себя.', 'error')
        return redirect('/admin#tab-users')
    u = User.query.filter_by(id=uid, org_id=org.id).first()
    if not u:
        flash('Пользователь не найден.', 'error')
        return redirect('/admin#tab-users')
    try:
        from models import RevisionItem, Revision
        RevisionItem.query.filter_by(added_by_user_id=u.id).update({'added_by_user_id': None}, synchronize_session=False)
        Revision.query.filter_by(user_id=u.id).delete(synchronize_session=False)
        db.session.delete(u)
        db.session.commit()
        flash('Пользователь удалён.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-users')


# ============== АДМИН: НОРМЫ ==============
@app.route('/admin/norms/save', methods=['POST'])
@admin_required
def admin_save_norms():
    org = _current_org()
    data = request.get_json(silent=True) or {}
    try:
        product_ids = {p.id for p in Product.query.filter_by(org_id=org.id).all()}
        location_ids = {l.id for l in Location.query.filter_by(org_id=org.id).all()}
        saved = 0
        for pid_s, loc_map in data.items():
            try:
                pid = int(pid_s)
            except (TypeError, ValueError):
                continue
            if pid not in product_ids:
                continue
            for lid_s, qty in (loc_map or {}).items():
                try:
                    lid = int(lid_s)
                    q = float(qty) if qty not in (None, '', 'null') else 0.0
                except (TypeError, ValueError):
                    continue
                if lid not in location_ids:
                    continue
                n = ProductNorm.query.filter_by(product_id=pid, location_id=lid).first()
                if q <= 0:
                    if n:
                        db.session.delete(n)
                        saved += 1
                    continue
                if n:
                    if n.norm_qty != q:
                        n.norm_qty = q
                        saved += 1
                else:
                    db.session.add(ProductNorm(product_id=pid, location_id=lid, norm_qty=q))
                    saved += 1
        db.session.commit()
        return jsonify({'ok': True, 'saved': saved})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400


# ============== АДМИН: ИМПОРТ ==============
IMPORT_COLUMNS = ['Категория', 'Название', 'Код', 'Ед. изм.']


@app.route('/admin/import/template')
@admin_required
def admin_import_template():
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = 'Товары'
    ws.append(IMPORT_COLUMNS)
    ws.append(['Напитки', 'Кола 0.5л', '', 'шт'])
    ws.append(['Напитки', 'Вода 0.5л', 'P-WATER-500', 'шт'])
    ws.append(['Булочки', 'Булочка бриошь', '', 'шт'])
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(
        buf, as_attachment=True, download_name='import_template.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


def _import_rows(org_id, rows):
    """rows — iterable of dict-like {Категория, Название, Код, Ед. изм.}."""
    added = 0
    skipped = 0
    errors = []

    cat_cache = {c.name: c for c in Category.query.filter_by(org_id=org_id).all()}
    existing_codes = {p.code for p in Product.query.filter_by(org_id=org_id).all() if p.code}
    existing_names = {(p.category_id, p.name.lower()) for p in Product.query.filter_by(org_id=org_id).all()}

    for i, row in enumerate(rows, start=2):
        try:
            cat_name = (row.get('Категория') or '').strip()
            name = (row.get('Название') or '').strip()
            code = (row.get('Код') or '').strip()
            unit = (row.get('Ед. изм.') or 'шт').strip() or 'шт'
            if not name:
                skipped += 1
                errors.append(f'Строка {i}: пустое название')
                continue

            cat_id = None
            if cat_name:
                c = cat_cache.get(cat_name)
                if not c:
                    max_order = db.session.query(db.func.max(Category.sort_order)).filter_by(org_id=org_id).scalar() or 0
                    c = Category(org_id=org_id, name=cat_name, sort_order=max_order + 1)
                    db.session.add(c)
                    db.session.flush()
                    cat_cache[cat_name] = c
                cat_id = c.id

            key = (cat_id, name.lower())
            if key in existing_names:
                skipped += 1
                errors.append(f'Строка {i}: дубликат «{name}»')
                continue

            if code:
                if code in existing_codes:
                    skipped += 1
                    errors.append(f'Строка {i}: код «{code}» занят')
                    continue
            else:
                code = _generate_product_code(org_id)
                while code in existing_codes:
                    # на случай конкуренции
                    num = int(code.rsplit('-', 1)[-1]) + 1
                    code = f'P{org_id}-{num:03d}'

            p = Product(org_id=org_id, name=name, category_id=cat_id, unit=unit, code=code)
            db.session.add(p)
            existing_codes.add(code)
            existing_names.add(key)
            added += 1
        except Exception as e:
            skipped += 1
            errors.append(f'Строка {i}: {e}')

    db.session.commit()
    return added, skipped, errors


@app.route('/admin/import/upload', methods=['POST'])
@admin_required
def admin_import_upload():
    org = _current_org()
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': 'Файл не выбран'}), 400

    filename = f.filename.lower()
    rows = []
    try:
        if filename.endswith('.xlsx'):
            from openpyxl import load_workbook
            wb = load_workbook(f, read_only=True, data_only=True)
            ws = wb.active
            headers = None
            for r in ws.iter_rows(values_only=True):
                if headers is None:
                    headers = [str(c).strip() if c is not None else '' for c in r]
                    continue
                if all(c is None or str(c).strip() == '' for c in r):
                    continue
                row = {}
                for idx, col in enumerate(headers):
                    if idx < len(r):
                        val = r[idx]
                        row[col] = '' if val is None else str(val)
                rows.append(row)
        elif filename.endswith('.csv'):
            data = f.read().decode('utf-8-sig', errors='replace')
            reader = csv.DictReader(io.StringIO(data))
            for row in reader:
                rows.append({k.strip() if k else '': (v or '') for k, v in row.items()})
        else:
            return jsonify({'ok': False, 'error': 'Поддерживаются только .xlsx и .csv'}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Ошибка чтения файла: {e}'}), 400

    try:
        added, skipped, errors = _import_rows(org.id, rows)
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400

    return jsonify({'ok': True, 'added': added, 'skipped': skipped, 'errors': errors[:20]})


# Предустановленные наборы товаров
PRESETS = {
    'burger': {
        'name': 'Бургерная',
        'items': [
            ('Напитки', 'Кола 0.5л', 'шт'), ('Напитки', 'Спрайт 0.5л', 'шт'),
            ('Напитки', 'Фанта 0.5л', 'шт'), ('Напитки', 'Вода 0.5л', 'шт'),
            ('Напитки', 'Сок яблочный', 'шт'), ('Напитки', 'Сок апельсиновый', 'шт'),
            ('Булочки', 'Булочка бриошь', 'шт'), ('Булочки', 'Булочка классик', 'шт'),
            ('Булочки', 'Булочка с кунжутом', 'шт'),
            ('Мясо', 'Котлета говяжья', 'шт'), ('Мясо', 'Котлета куриная', 'шт'),
            ('Мясо', 'Бекон', 'г'),
            ('Соусы', 'Кетчуп', 'г'), ('Соусы', 'Майонез', 'г'),
            ('Соусы', 'Горчица', 'г'), ('Соусы', 'Соус барбекю', 'г'),
            ('Соусы', 'Соус сырный', 'г'),
            ('Овощи', 'Лук', 'г'), ('Овощи', 'Помидор', 'г'),
            ('Овощи', 'Огурец', 'г'), ('Овощи', 'Салат', 'г'),
            ('Овощи', 'Сыр чеддер', 'шт'), ('Овощи', 'Сыр моцарелла', 'шт'),
            ('Картофель', 'Фри', 'г'), ('Картофель', 'Наггетсы', 'шт'),
        ],
    },
    'coffee': {
        'name': 'Кофейня',
        'items': [
            ('Кофе', 'Эспрессо', 'г'), ('Кофе', 'Арабика зерно', 'г'),
            ('Кофе', 'Робуста зерно', 'г'),
            ('Молоко', 'Молоко 3.2%', 'мл'), ('Молоко', 'Молоко растительное', 'мл'),
            ('Молоко', 'Сливки', 'мл'),
            ('Сиропы', 'Сироп ваниль', 'мл'), ('Сиропы', 'Сироп карамель', 'мл'),
            ('Сиропы', 'Сироп орех', 'мл'),
            ('Напитки', 'Чай черный', 'шт'), ('Напитки', 'Чай зеленый', 'шт'),
            ('Напитки', 'Какао', 'г'),
            ('Десерты', 'Круассан', 'шт'), ('Десерты', 'Маффин', 'шт'),
            ('Десерты', 'Чизкейк', 'шт'),
            ('Расходники', 'Стакан 200мл', 'шт'), ('Расходники', 'Стакан 300мл', 'шт'),
            ('Расходники', 'Крышка', 'шт'), ('Расходники', 'Трубочка', 'шт'),
        ],
    },
    'bakery': {
        'name': 'Пекарня',
        'items': [
            ('Мука', 'Мука пшеничная', 'кг'), ('Мука', 'Мука ржаная', 'кг'),
            ('Мука', 'Мука цельнозерновая', 'кг'),
            ('Хлеб', 'Батон', 'шт'), ('Хлеб', 'Хлеб белый', 'шт'),
            ('Хлеб', 'Хлеб ржаной', 'шт'), ('Хлеб', 'Багет', 'шт'),
            ('Выпечка', 'Круассан', 'шт'), ('Выпечка', 'Булочка с корицей', 'шт'),
            ('Выпечка', 'Слойка с яблоком', 'шт'), ('Выпечка', 'Плюшка', 'шт'),
            ('Торты', 'Наполеон', 'шт'), ('Торты', 'Медовик', 'шт'),
            ('Торты', 'Чизкейк', 'шт'),
            ('Ингредиенты', 'Масло сливочное', 'г'), ('Ингредиенты', 'Сахар', 'кг'),
            ('Ингредиенты', 'Дрожжи', 'г'), ('Ингредиенты', 'Яйца', 'шт'),
        ],
    },
    'sushi': {
        'name': 'Суши',
        'items': [
            ('Рис', 'Рис суши', 'кг'), ('Рис', 'Уксус рисовый', 'мл'),
            ('Рыба', 'Лосось', 'г'), ('Рыба', 'Тунец', 'г'),
            ('Рыба', 'Угорь', 'г'), ('Рыба', 'Креветки', 'шт'),
            ('Овощи', 'Огурец', 'шт'), ('Овощи', 'Авокадо', 'шт'),
            ('Овощи', 'Зелень', 'г'),
            ('Нори', 'Нори', 'лист'),
            ('Соусы', 'Соевый соус', 'мл'), ('Соусы', 'Васаби', 'г'),
            ('Соусы', 'Имбирь', 'г'), ('Соусы', 'Унаги', 'мл'),
            ('Упаковка', 'Контейнер', 'шт'), ('Упаковка', 'Палочки', 'пара'),
        ],
    },
}


@app.route('/admin/import/preset/<ptype>', methods=['POST'])
@admin_required
def admin_import_preset(ptype):
    preset = PRESETS.get(ptype)
    if not preset:
        flash('Неизвестный тип заведения.', 'error')
        return redirect('/admin#tab-import')
    org = _current_org()
    rows = [{'Категория': c, 'Название': n, 'Код': '', 'Ед. изм.': u} for c, n, u in preset['items']]
    try:
        added, skipped, _ = _import_rows(org.id, rows)
        flash(f'Шаблон «{preset["name"]}» применён: добавлено {added}, пропущено {skipped}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-import')


# ============== РЕВИЗИЯ (ОПЕРАТОР/АДМИН) ==============
@app.route('/revision')
@login_required_user
def revision():
    org = _current_org()
    if not org:
        return redirect('/login')

    locations = Location.query.filter_by(org_id=org.id).order_by(Location.sort_order, Location.name).all()
    categories = Category.query.filter_by(org_id=org.id).order_by(Category.sort_order, Category.name).all()
    products = Product.query.filter_by(org_id=org.id, is_active=True).order_by(Product.name).all()

    # Выбранная локация (по ?location=Name) — иначе первая
    selected_name = request.args.get('location')
    selected_loc = None
    if selected_name:
        selected_loc = next((l for l in locations if l.name == selected_name), None)
    if not selected_loc and locations:
        selected_loc = locations[0]

    # Нормы для всех товаров этой локации
    norms_map = {}  # product_id -> norm_qty
    if selected_loc and products:
        for n in ProductNorm.query.filter_by(location_id=selected_loc.id).all():
            norms_map[n.product_id] = n.norm_qty

    # Активная ревизия локации (не создаём — только читаем)
    current_rev = None
    qty_map = {}  # product_id -> сумма quantity в активной ревизии на этой локации
    if selected_loc:
        current_rev = Revision.query.filter_by(
            org_id=org.id, location_id=selected_loc.id, status='in_progress'
        ).first()
        if current_rev:
            items = RevisionItem.query.filter_by(
                revision_id=current_rev.id, location_id=selected_loc.id
            ).all()
            for it in items:
                qty_map[it.product_id] = qty_map.get(it.product_id, 0) + (it.quantity or 0)

    # Группировка товаров по категориям (с учётом "без категории")
    cat_map = {c.id: c for c in categories}
    grouped = {}
    for p in products:
        grouped.setdefault(p.category_id, []).append(p)
    # Упорядоченный список (cat_obj или None, [products...])
    grouped_ordered = []
    for c in categories:
        items = grouped.get(c.id)
        if items:
            grouped_ordered.append((c, items))
    if grouped.get(None):
        grouped_ordered.append((None, grouped[None]))

    is_admin = (current_user.user and current_user.user.role == 'admin')

    return render_template_string(
        revision_html,
        org=org,
        username=current_user.username,
        locations=locations,
        selected=selected_loc,
        grouped=grouped_ordered,
        qty_map=qty_map,
        norms_map=norms_map,
        is_admin=is_admin,
        rev_status=(current_rev.status if current_rev else None),
    )


@app.route('/revision/add', methods=['POST'])
@login_required_user
def revision_add():
    org = _current_org()
    if not org:
        return jsonify({'ok': False, 'error': 'no org'}), 400
    try:
        location_id = int(request.form.get('location_id') or 0)
        product_id = int(request.form.get('product_id') or 0)
        count = float(request.form.get('count') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'bad params'}), 400

    if count <= 0:
        return jsonify({'ok': False, 'error': 'count must be > 0'}), 400

    loc = Location.query.filter_by(id=location_id, org_id=org.id).first()
    prod = Product.query.filter_by(id=product_id, org_id=org.id).first()
    if not loc or not prod:
        return jsonify({'ok': False, 'error': 'not found'}), 404

    try:
        rev = _get_or_create_active_revision(org.id, loc.id, current_user.raw_id)
        item = RevisionItem(
            revision_id=rev.id,
            product_id=prod.id,
            location_id=loc.id,
            quantity=count,
            added_by_user_id=current_user.raw_id,
        )
        db.session.add(item)
        db.session.commit()
        # Пересчитать суммарное количество
        total = db.session.query(db.func.coalesce(db.func.sum(RevisionItem.quantity), 0)).filter_by(
            revision_id=rev.id, product_id=prod.id, location_id=loc.id
        ).scalar() or 0
        return jsonify({'ok': True, 'total': float(total), 'revision_id': rev.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/revision/finish', methods=['POST'])
@login_required_user
def revision_finish():
    org = _current_org()
    if not org:
        return jsonify({'ok': False, 'error': 'no org'}), 400
    try:
        location_id = int(request.form.get('location_id') or request.args.get('location_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'bad location_id'}), 400

    loc = Location.query.filter_by(id=location_id, org_id=org.id).first()
    if not loc:
        return jsonify({'ok': False, 'error': 'location not found'}), 404

    rev = Revision.query.filter_by(
        org_id=org.id, location_id=loc.id, status='in_progress'
    ).first()
    if not rev:
        return jsonify({'ok': False, 'error': 'Нет активной ревизии на этой локации'}), 400

    cnt = RevisionItem.query.filter_by(revision_id=rev.id).count()
    if cnt == 0:
        return jsonify({'ok': False, 'error': 'Ревизия пуста'}), 400

    try:
        rev.status = 'pending'
        rev.finished_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'ok': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/revision/delete_item/<int:item_id>', methods=['POST'])
@login_required_user
def revision_delete_item(item_id):
    org = _current_org()
    if not org:
        return jsonify({'ok': False, 'error': 'no org'}), 400
    item = RevisionItem.query.get(item_id)
    if not item:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    # Проверка, что запись принадлежит нашей организации
    rev = db.session.get(Revision, item.revision_id)
    if not rev or rev.org_id != org.id:
        return jsonify({'ok': False, 'error': 'forbidden'}), 403
    # Только свою запись — или админ
    is_admin = (current_user.user and current_user.user.role == 'admin')
    if not is_admin and item.added_by_user_id != current_user.raw_id:
        return jsonify({'ok': False, 'error': 'forbidden'}), 403

    product_id = item.product_id
    location_id = item.location_id
    revision_id = item.revision_id
    try:
        db.session.delete(item)
        db.session.commit()
        total = db.session.query(db.func.coalesce(db.func.sum(RevisionItem.quantity), 0)).filter_by(
            revision_id=revision_id, product_id=product_id, location_id=location_id,
        ).scalar() or 0
        return jsonify({'ok': True, 'total': float(total)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/revision/product_history/<int:product_id>')
@login_required_user
def revision_product_history(product_id):
    org = _current_org()
    if not org:
        return jsonify({'ok': False, 'items': []}), 400
    try:
        location_id = int(request.args.get('location_id') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'items': []}), 400

    prod = Product.query.filter_by(id=product_id, org_id=org.id).first()
    loc = Location.query.filter_by(id=location_id, org_id=org.id).first()
    if not prod or not loc:
        return jsonify({'ok': True, 'items': [], 'total': 0})

    rev = Revision.query.filter_by(
        org_id=org.id, location_id=loc.id, status='in_progress'
    ).first()
    if not rev:
        return jsonify({'ok': True, 'items': [], 'total': 0})

    items = (
        RevisionItem.query.filter_by(
            revision_id=rev.id, product_id=prod.id, location_id=loc.id
        ).order_by(RevisionItem.added_at.asc()).all()
    )
    user_ids = {i.added_by_user_id for i in items if i.added_by_user_id}
    users = {}
    if user_ids:
        for u in User.query.filter(User.id.in_(user_ids)).all():
            users[u.id] = u.username

    current_uid = current_user.raw_id
    is_admin = (current_user.user and current_user.user.role == 'admin')

    out = []
    total = 0.0
    for it in items:
        uname = users.get(it.added_by_user_id, '—')
        can_delete = is_admin or (it.added_by_user_id == current_uid)
        ts = it.added_at.strftime('%d.%m %H:%M') if it.added_at else ''
        out.append({
            'id': it.id,
            'quantity': it.quantity,
            'user': uname,
            'timestamp': ts,
            'can_delete': can_delete,
            'text': f'{ts}: {uname} добавил {it.quantity}',
        })
        total += (it.quantity or 0)
    return jsonify({'ok': True, 'items': out, 'total': total})


# ============== АДМИН: РЕВИЗИИ (ЗАПРОСЫ/ИСТОРИЯ) ==============
def _build_revision_xlsx(rev):
    """Сгенерировать xlsx со сгруппированными итогами ревизии."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    org = db.session.get(Organization, rev.org_id)
    loc = db.session.get(Location, rev.location_id) if rev.location_id else None
    user = db.session.get(User, rev.user_id) if rev.user_id else None

    items = RevisionItem.query.filter_by(revision_id=rev.id).all()

    # Собрать все product_id, category_id
    pids = {i.product_id for i in items}
    products = {p.id: p for p in Product.query.filter(Product.id.in_(pids)).all()} if pids else {}
    cat_ids = {p.category_id for p in products.values() if p.category_id}
    cats = {c.id: c for c in Category.query.filter(Category.id.in_(cat_ids)).all()} if cat_ids else {}

    # Агрегация: cat_name -> list of (code, name, unit, total_qty)
    grouped = {}
    for it in items:
        p = products.get(it.product_id)
        if not p:
            continue
        c = cats.get(p.category_id) if p.category_id else None
        cat_name = c.name if c else 'Без категории'
        key = (cat_name, p.id)
        grouped.setdefault(cat_name, {})
        grouped[cat_name].setdefault(p.id, {
            'code': p.code or '', 'name': p.name, 'unit': p.unit, 'qty': 0,
        })
        grouped[cat_name][p.id]['qty'] += (it.quantity or 0)

    wb = Workbook()
    ws = wb.active
    ws.title = 'Ревизия'

    bold = Font(bold=True)
    header_fill = PatternFill('solid', fgColor='7C6CF0')
    cat_fill = PatternFill('solid', fgColor='EDE9FE')
    thin = Side(border_style='thin', color='CCCCCC')
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    # Метаинформация
    ws['A1'] = 'Бланк инвентаризации'
    ws['A1'].font = Font(bold=True, size=16)
    ws.merge_cells('A1:E1')
    date_str = (rev.finished_at or rev.created_at or datetime.utcnow()).strftime('%d.%m.%Y %H:%M')
    ws['A3'] = 'Дата:'
    ws['B3'] = date_str
    ws['A4'] = 'Компания:'
    ws['B4'] = org.name if org else ''
    ws['A5'] = 'Локация:'
    ws['B5'] = loc.name if loc else '—'
    ws['A6'] = 'Оператор:'
    ws['B6'] = user.username if user else '—'

    header_row = 8
    headers = ['Код', 'Наименование', 'Ед. изм.', 'Категория', 'Остаток фактический']
    for i, h in enumerate(headers, start=1):
        c = ws.cell(row=header_row, column=i, value=h)
        c.font = Font(bold=True, color='FFFFFF')
        c.fill = header_fill
        c.alignment = Alignment(horizontal='center')
        c.border = border

    r = header_row + 1
    for cat_name in sorted(grouped.keys()):
        # Строка-заголовок категории
        cc = ws.cell(row=r, column=1, value=cat_name)
        cc.font = bold
        cc.fill = cat_fill
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
        r += 1
        for _pid, info in sorted(grouped[cat_name].items(), key=lambda kv: kv[1]['name']):
            ws.cell(row=r, column=1, value=info['code']).border = border
            ws.cell(row=r, column=2, value=info['name']).border = border
            ws.cell(row=r, column=3, value=info['unit']).border = border
            ws.cell(row=r, column=4, value=cat_name).border = border
            ws.cell(row=r, column=5, value=info['qty']).border = border
            r += 1

    # Автоширина — упрощённо
    widths = {1: 14, 2: 48, 3: 12, 4: 22, 5: 22}
    for col, w in widths.items():
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = w

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


@app.route('/admin/revisions/confirm/<int:rev_id>', methods=['POST'])
@admin_required
def admin_revision_confirm(rev_id):
    org = _current_org()
    rev = Revision.query.filter_by(id=rev_id, org_id=org.id).first()
    if not rev:
        flash('Ревизия не найдена.', 'error')
        return redirect('/admin#tab-requests')
    if rev.status != 'pending':
        flash('Ревизия не в статусе ожидания.', 'error')
        return redirect('/admin#tab-requests')
    try:
        buf = _build_revision_xlsx(rev)
        rev.status = 'completed'
        if not rev.finished_at:
            rev.finished_at = datetime.utcnow()
        db.session.commit()
        loc = db.session.get(Location, rev.location_id) if rev.location_id else None
        loc_name = (loc.name if loc else 'location').replace(' ', '_')
        date_str = (rev.finished_at or datetime.utcnow()).strftime('%Y%m%d_%H%M')
        fname = f'revision_{loc_name}_{date_str}.xlsx'
        return send_file(
            buf, as_attachment=True, download_name=fname,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        )
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
        return redirect('/admin#tab-requests')


@app.route('/admin/revisions/reject/<int:rev_id>', methods=['POST'])
@admin_required
def admin_revision_reject(rev_id):
    org = _current_org()
    rev = Revision.query.filter_by(id=rev_id, org_id=org.id).first()
    if not rev:
        flash('Ревизия не найдена.', 'error')
        return redirect('/admin#tab-requests')
    if rev.status != 'pending':
        flash('Ревизия не в статусе ожидания.', 'error')
        return redirect('/admin#tab-requests')
    try:
        rev.status = 'cancelled'
        rev.finished_at = datetime.utcnow()
        db.session.commit()
        flash('Запрос отклонён.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/admin#tab-requests')


@app.route('/admin/revisions/<int:rev_id>/download')
@admin_required
def admin_revision_download(rev_id):
    org = _current_org()
    rev = Revision.query.filter_by(id=rev_id, org_id=org.id).first()
    if not rev:
        abort(404)
    buf = _build_revision_xlsx(rev)
    loc = db.session.get(Location, rev.location_id) if rev.location_id else None
    loc_name = (loc.name if loc else 'location').replace(' ', '_')
    date_str = (rev.finished_at or rev.created_at or datetime.utcnow()).strftime('%Y%m%d_%H%M')
    fname = f'revision_{loc_name}_{date_str}.xlsx'
    return send_file(
        buf, as_attachment=True, download_name=fname,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


# ============== CLI КОМАНДЫ ==============
@app.cli.command('seed-demo')
def seed_demo():
    """Создать демо-организацию."""
    email = 'demo@spurt.dev'
    if Organization.query.filter_by(owner_email=email).first():
        click.echo('Демо-организация уже существует.')
        return

    org = Organization(
        name='Демо Бургерная',
        owner_email=email,
        email_verified=True,
        plan='trial',
        trial_ends_at=datetime.utcnow() + timedelta(days=30),
    )
    db.session.add(org)
    db.session.flush()

    admin = User(org_id=org.id, username='admin', email=email, role='admin')
    admin.set_password('demo123')
    db.session.add(admin)

    for order, loc_name in enumerate(('Склад', 'Кухня', 'Островок')):
        db.session.add(Location(org_id=org.id, name=loc_name, sort_order=order))

    db.session.commit()
    click.echo('✔ Демо-организация создана.')
    click.echo(f'  Email:    {email}')
    click.echo('  Username: admin')
    click.echo('  Password: demo123')


@app.cli.command('create-owner')
def create_owner():
    """Создать супер-админа (владельца системы)."""
    email = click.prompt('Email').strip().lower()
    password = click.prompt('Password', hide_input=True, confirmation_prompt=True)

    if OwnerUser.query.filter_by(email=email).first():
        click.echo('Владелец с таким email уже существует.')
        return

    owner = OwnerUser(email=email)
    owner.set_password(password)
    db.session.add(owner)
    db.session.commit()
    click.echo(f'✔ OwnerUser создан: {email}')


# ============== OWNER PANEL ==============

def owner_required(fn):
    """Decorator: only authenticated OwnerUser may access this route."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'owner':
            return redirect('/owner/login')
        return fn(*args, **kwargs)
    return wrapper


@app.route('/owner/login', methods=['GET', 'POST'])
def owner_login():
    error = None
    if current_user.is_authenticated and current_user.user_type == 'owner':
        return redirect('/owner')

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        ip = request.remote_addr or 'unknown'

        owner = OwnerUser.query.filter_by(email=email).first()
        if not owner or not owner.check_password(password):
            log_attempt(ip, email, False)
            error = 'Неверный email или пароль.'
        else:
            log_attempt(ip, email, True)
            login_user(AuthUser(owner, 'owner'))
            return redirect('/owner')

    return render_template_string(owner_login_html, error=error)


@app.route('/owner/logout')
def owner_logout():
    logout_user()
    return redirect('/owner/login')


@app.route('/owner')
@owner_required
def owner_dashboard():
    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=7)

    total_orgs = Organization.query.count()

    # Активные: есть пользователь с last_login_at за последние 7 дней
    active_org_ids = db.session.query(User.org_id).filter(
        User.last_login_at >= seven_days_ago
    ).distinct().subquery()
    active_orgs = db.session.query(db.func.count()).select_from(
        Organization
    ).filter(Organization.id.in_(active_org_ids)).scalar() or 0

    # На trial
    trial_orgs = Organization.query.filter(
        Organization.plan == 'trial',
        Organization.trial_ends_at > now,
    ).count()

    # Платящих
    paying_orgs = Organization.query.filter(
        Organization.plan.in_(('pro', 'business')),
        Organization.subscription_ends_at > now,
    ).count()

    # Trial заканчивается в ближайшие 3 дня
    in_3_days = now + timedelta(days=3)
    expiring_soon = Organization.query.filter(
        Organization.plan == 'trial',
        Organization.trial_ends_at > now,
        Organization.trial_ends_at <= in_3_days,
    ).all()

    expiring_list = []
    for org in expiring_soon:
        delta = org.trial_ends_at - now
        days_left = max(0, delta.days)
        expiring_list.append({
            'id': org.id,
            'name': org.name,
            'email': org.owner_email,
            'days_left': days_left,
        })

    # Последние 5 регистраций
    recent_orgs = Organization.query.order_by(Organization.created_at.desc()).limit(5).all()
    recent_list = []
    for org in recent_orgs:
        recent_list.append({
            'name': org.name,
            'email': org.owner_email,
            'plan': org.plan,
            'created_at': org.created_at.strftime('%d.%m.%Y') if org.created_at else '—',
        })

    # Активность сегодня
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    activity_today = RevisionItem.query.filter(RevisionItem.added_at >= today_start).count()

    return render_template_string(
        owner_dashboard_html,
        owner_email=current_user.username,
        total_orgs=total_orgs,
        active_orgs=active_orgs,
        trial_orgs=trial_orgs,
        paying_orgs=paying_orgs,
        expiring_list=expiring_list,
        recent_list=recent_list,
        activity_today=activity_today,
    )


@app.route('/owner/orgs')
@owner_required
def owner_orgs():
    orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    now = datetime.utcnow()

    org_rows = []
    for org in orgs:
        users = User.query.filter_by(org_id=org.id).all()
        user_count = len(users)
        last_login = None
        for u in users:
            if u.last_login_at:
                if last_login is None or u.last_login_at > last_login:
                    last_login = u.last_login_at

        if org.plan == 'trial' and org.trial_ends_at:
            ends_str = org.trial_ends_at.strftime('%d.%m.%Y')
        elif org.plan in ('pro', 'business') and org.subscription_ends_at:
            ends_str = org.subscription_ends_at.strftime('%d.%m.%Y')
        else:
            ends_str = '—'

        org_rows.append({
            'id': org.id,
            'name': org.name,
            'email': org.owner_email,
            'plan': org.plan,
            'ends': ends_str,
            'user_count': user_count,
            'last_activity': last_login.strftime('%d.%m.%Y %H:%M') if last_login else 'никогда',
            'is_blocked': org.is_blocked,
        })

    return render_template_string(
        owner_orgs_html,
        owner_email=current_user.username,
        org_rows=org_rows,
    )


@app.route('/owner/orgs/<int:org_id>/extend_trial', methods=['POST'])
@owner_required
def owner_extend_trial(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        flash('Компания не найдена.', 'error')
        return redirect('/owner/orgs')
    now = datetime.utcnow()
    if org.trial_ends_at and org.trial_ends_at > now:
        org.trial_ends_at = org.trial_ends_at + timedelta(days=7)
    else:
        org.trial_ends_at = now + timedelta(days=7)
    org.plan = 'trial'
    try:
        db.session.commit()
        flash(f'Trial компании «{org.name}» продлён на 7 дней.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/owner/orgs')


@app.route('/owner/orgs/<int:org_id>/set_plan', methods=['POST'])
@owner_required
def owner_set_plan(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        flash('Компания не найдена.', 'error')
        return redirect('/owner/orgs')
    plan = (request.form.get('plan') or '').lower()
    if plan not in ('free', 'trial', 'pro', 'business'):
        flash('Неизвестный тариф.', 'error')
        return redirect('/owner/orgs')
    org.plan = plan
    if plan in ('pro', 'business'):
        org.subscription_ends_at = datetime.utcnow() + timedelta(days=30)
    try:
        db.session.commit()
        flash(f'Тариф компании «{org.name}» изменён на {plan.upper()}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/owner/orgs')


@app.route('/owner/orgs/<int:org_id>/toggle_block', methods=['POST'])
@owner_required
def owner_toggle_block(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        flash('Компания не найдена.', 'error')
        return redirect('/owner/orgs')
    org.is_blocked = not org.is_blocked
    action = 'заблокирована' if org.is_blocked else 'разблокирована'
    try:
        db.session.commit()
        flash(f'Компания «{org.name}» {action}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {e}', 'error')
    return redirect('/owner/orgs')


@app.route('/owner/orgs/<int:org_id>/delete', methods=['POST'])
@owner_required
def owner_delete_org(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        flash('Компания не найдена.', 'error')
        return redirect('/owner/orgs')
    name = org.name
    try:
        db.session.delete(org)
        db.session.commit()
        flash(f'Компания «{name}» и все её данные удалены.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка удаления: {e}', 'error')
    return redirect('/owner/orgs')


# ============== HTML ШАБЛОНЫ ==============

_BASE_CSS = '''
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
body {
    font-family: 'Outfit', sans-serif;
    background: linear-gradient(135deg, #13111C 0%, #1d1635 50%, #231b50 100%);
    background-attachment: fixed;
    min-height: 100vh;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    position: relative;
    overflow-x: hidden;
}
.blob { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.35; pointer-events: none; z-index: 0; }
.blob-1 { width: 400px; height: 400px; background: radial-gradient(circle, #7c6cf0, #a855f7); top: -100px; left: -100px; }
.blob-2 { width: 350px; height: 350px; background: radial-gradient(circle, #a855f7, #6d28d9); bottom: -80px; right: -80px; }
.blob-3 { width: 250px; height: 250px; background: radial-gradient(circle, #818cf8, #7c6cf0); top: 50%; left: 50%; transform: translate(-50%, -50%); }
.card {
    background: rgba(255,255,255,0.07);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 24px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.4);
    padding: 40px 32px;
    max-width: 440px;
    width: 100%;
    position: relative;
    z-index: 1;
    animation: fadeIn 0.5s ease-out;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
.title { text-align: center; color: white; font-weight: 700; font-size: 26px; margin-bottom: 6px; }
.subtitle { text-align: center; color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 28px; }
.form-group { margin-bottom: 16px; }
.form-group label {
    display: block; margin-bottom: 6px; font-weight: 600;
    color: rgba(255,255,255,0.55); font-size: 12px;
    text-transform: uppercase; letter-spacing: 0.8px;
}
.input {
    width: 100%;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 14px;
    color: white;
    padding: 14px 16px;
    font-family: 'Outfit', sans-serif;
    font-size: 15px;
    transition: all 0.2s;
}
.input::placeholder { color: rgba(255,255,255,0.3); }
.input:focus {
    border-color: rgba(124,108,240,0.7);
    background: rgba(124,108,240,0.12);
    outline: none;
    box-shadow: 0 0 0 3px rgba(124,108,240,0.2);
}
.hint { font-size: 11px; color: rgba(255,255,255,0.4); margin-top: 4px; padding-left: 2px; }
.btn-primary {
    width: 100%;
    background: linear-gradient(135deg, #7c6cf0, #a855f7);
    color: white;
    border: none;
    padding: 15px;
    border-radius: 14px;
    font-weight: 600;
    font-size: 16px;
    font-family: 'Outfit', sans-serif;
    cursor: pointer;
    box-shadow: 0 6px 24px rgba(124,108,240,0.4);
    margin-top: 6px;
    transition: transform 0.1s;
}
.btn-primary:active { transform: scale(0.98); }
.error {
    color: #fca5a5;
    background: rgba(239,68,68,0.12);
    border: 1px solid rgba(239,68,68,0.3);
    padding: 12px 16px;
    border-radius: 12px;
    margin-bottom: 18px;
    text-align: center;
    font-size: 14px;
}
.link { color: #a78bfa; text-decoration: none; font-weight: 600; }
.link:hover { color: #c4b5fd; }
.bottom-link {
    text-align: center;
    margin-top: 20px;
    font-size: 14px;
    color: rgba(255,255,255,0.55);
}
.checkbox-row {
    display: flex; align-items: flex-start; gap: 10px;
    color: rgba(255,255,255,0.7); font-size: 13px;
    margin: 4px 0 14px; cursor: pointer;
}
.checkbox-row input { margin-top: 3px; accent-color: #7c6cf0; }
.icon-box {
    width: 64px; height: 64px;
    margin: 0 auto 18px;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(124,108,240,0.5);
    border-radius: 18px;
    display: flex; align-items: center; justify-content: center;
    font-size: 30px;
    box-shadow: 0 0 24px rgba(124,108,240,0.3);
}
'''


register_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Регистрация компании — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card">
  <div class="icon-box">🚀</div>
  <div class="title">Регистрация компании</div>
  <div class="subtitle">14 дней бесплатно, без карты</div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post">
    <div class="form-group">
      <label>Название компании</label>
      <input class="input" type="text" name="company" required placeholder="ООО Ромашка">
    </div>
    <div class="form-group">
      <label>Email владельца</label>
      <input class="input" type="email" name="email" required placeholder="owner@example.com">
    </div>
    <div class="form-group">
      <label>Ваш логин</label>
      <input class="input" type="text" name="username" required placeholder="admin">
      <div class="hint">Этот логин вы будете использовать для входа</div>
    </div>
    <div class="form-group">
      <label>Пароль</label>
      <input class="input" type="password" name="password" required minlength="6" placeholder="Минимум 6 символов">
    </div>
    <div class="form-group">
      <label>Повторите пароль</label>
      <input class="input" type="password" name="password2" required minlength="6" placeholder="Ещё раз">
    </div>
    <label class="checkbox-row">
      <input type="checkbox" name="terms" value="1" required>
      <span>Согласен с условиями использования</span>
    </label>
    <button class="btn-primary" type="submit">Создать аккаунт →</button>
  </form>
  <div class="bottom-link">
    Уже есть аккаунт? <a class="link" href="/login">Войти</a>
  </div>
</div>
</body>
</html>'''


register_success_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Проверьте email — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card">
  <div class="icon-box">📧</div>
  <div class="title">Проверьте email</div>
  <div class="subtitle">Мы отправили ссылку для подтверждения на указанный email</div>
  {% if verify_url %}
  <div style="background: rgba(124,108,240,0.12); border: 1px solid rgba(124,108,240,0.3);
              border-radius: 14px; padding: 16px; margin: 16px 0; font-size: 13px;
              color: rgba(255,255,255,0.75); text-align: center;">
    <div style="margin-bottom:10px;color:rgba(255,255,255,0.5);">Dev-режим: SMTP ещё не настроен.</div>
    <a class="link" href="{{ verify_url }}">Подтвердить сейчас →</a>
  </div>
  {% endif %}
  <div class="bottom-link">
    <a class="link" href="/login">Вернуться ко входу</a>
  </div>
</div>
</body>
</html>'''


message_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card">
  <div class="icon-box">⚠️</div>
  <div class="title">{{ title }}</div>
  <div class="subtitle">{{ text }}</div>
  <div class="bottom-link"><a class="link" href="/login">На главную</a></div>
</div>
</body>
</html>'''


placeholder_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''
.info-row {
    display: flex; justify-content: space-between;
    padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.07);
    font-size: 14px;
}
.info-row:last-child { border-bottom: none; }
.info-row .k { color: rgba(255,255,255,0.5); }
.info-row .v { color: white; font-weight: 600; }
.logout-btn {
    display: inline-block; margin-top: 18px;
    background: rgba(239,68,68,0.15);
    color: #fca5a5;
    border: 1px solid rgba(239,68,68,0.25);
    padding: 12px 24px;
    border-radius: 12px;
    text-decoration: none;
    font-weight: 600;
    font-size: 14px;
}
.logout-btn:hover { background: rgba(239,68,68,0.25); }
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card" style="text-align:center;">
  <div class="icon-box">🏗️</div>
  <div class="title">{{ title }}</div>
  <div class="subtitle">Раздел в разработке. Вернитесь позже.</div>
  <div style="text-align:left; margin: 18px 0;">
    <div class="info-row"><span class="k">Пользователь</span><span class="v">{{ username }}</span></div>
    <div class="info-row"><span class="k">Компания</span><span class="v">{{ org_name }}</span></div>
    <div class="info-row"><span class="k">Trial дней осталось</span><span class="v">{{ days_left }}</span></div>
  </div>
  <a class="logout-btn" href="/logout">Выйти</a>
</div>
</body>
</html>'''


login_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Вход — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''
.version { text-align: center; color: rgba(255,255,255,0.2); font-size: 11px; margin-top: 20px; }
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card">
  <div class="icon-box">🏪</div>
  <div class="title">Инвентаризация</div>
  <div class="subtitle">Система учёта товаров</div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post">
    <div class="form-group">
      <label>Email компании</label>
      <input class="input" type="email" name="email" required autocomplete="email" placeholder="company@example.com">
      <div class="hint">Email вашей компании (тот, на который регистрировались)</div>
    </div>
    <div class="form-group">
      <label>Логин</label>
      <input class="input" type="text" name="username" required autocomplete="username" placeholder="Введите логин">
    </div>
    <div class="form-group">
      <label>Пароль</label>
      <input class="input" type="password" name="password" required autocomplete="current-password" placeholder="Введите пароль">
    </div>
    <button class="btn-primary" type="submit">Войти →</button>
  </form>
  <div class="bottom-link">
    Нет аккаунта? <a class="link" href="/register">Зарегистрировать компанию</a>
  </div>
  <div class="version">Версия: {{ now }}</div>
</div>
</body>
</html>'''


# ============== АДМИН ПАНЕЛЬ ==============
admin_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Админ панель — {{ org.name }}</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }
body {
  font-family: 'Outfit', sans-serif;
  background: linear-gradient(135deg, #13111C 0%, #1d1635 50%, #231b50 100%);
  background-attachment: fixed;
  min-height: 100vh;
  color: white;
  padding-bottom: 60px;
}
.blob { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.25; pointer-events: none; z-index: 0; }
.blob-1 { width: 400px; height: 400px; background: radial-gradient(circle, #7c6cf0, #a855f7); top: -100px; left: -100px; }
.blob-2 { width: 350px; height: 350px; background: radial-gradient(circle, #a855f7, #6d28d9); bottom: -80px; right: -80px; }
.header {
  position: sticky; top: 0; z-index: 20;
  background: rgba(19,17,28,0.75);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid rgba(255,255,255,0.08);
  padding: 14px 20px;
  display: flex; align-items: center; gap: 12px; justify-content: space-between;
}
.header .brand { display: flex; flex-direction: column; min-width: 0; }
.header .brand .name { font-weight: 700; font-size: 17px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.header .brand .sub { font-size: 11px; color: rgba(255,255,255,0.5); text-transform: uppercase; letter-spacing: 0.6px; }
.header .actions { display: flex; gap: 8px; }
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(255,255,255,0.07);
  border: 1px solid rgba(255,255,255,0.12);
  color: white;
  padding: 9px 14px;
  border-radius: 12px;
  font-family: 'Outfit', sans-serif;
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.15s;
}
.btn:hover { background: rgba(255,255,255,0.12); }
.btn-primary {
  background: linear-gradient(135deg, #7c6cf0, #a855f7);
  border-color: transparent;
  box-shadow: 0 6px 18px rgba(124,108,240,0.3);
}
.btn-primary:hover { filter: brightness(1.08); }
.btn-danger {
  background: rgba(239,68,68,0.12);
  border-color: rgba(239,68,68,0.3);
  color: #fca5a5;
}
.btn-danger:hover { background: rgba(239,68,68,0.22); }
.btn-small { padding: 6px 10px; font-size: 12px; }
.tabs-wrap {
  position: sticky; top: 60px; z-index: 15;
  background: rgba(19,17,28,0.65);
  backdrop-filter: blur(18px);
  border-bottom: 1px solid rgba(255,255,255,0.06);
  padding: 10px 16px;
}
.tabs {
  display: flex; gap: 8px;
  overflow-x: auto; scrollbar-width: none;
  padding-bottom: 4px;
}
.tabs::-webkit-scrollbar { display: none; }
.tab-pill {
  white-space: nowrap;
  padding: 9px 16px;
  border-radius: 20px;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.1);
  color: rgba(255,255,255,0.75);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}
.tab-pill.active {
  background: linear-gradient(135deg, #7c6cf0, #a855f7);
  color: white;
  border-color: transparent;
  box-shadow: 0 4px 12px rgba(124,108,240,0.35);
}
.container { max-width: 980px; margin: 20px auto; padding: 0 16px; position: relative; z-index: 1; }
.card {
  background: rgba(255,255,255,0.07);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 20px;
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.3);
}
.card h2 { font-size: 17px; margin-bottom: 14px; font-weight: 700; }
.card h3 { font-size: 14px; margin-bottom: 10px; font-weight: 600; color: rgba(255,255,255,0.85); }
.tab-content { display: none; }
.tab-content.active { display: block; animation: fadeIn 0.25s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
.flash-box {
  padding: 12px 14px; border-radius: 12px; margin-bottom: 12px;
  font-size: 13px; border: 1px solid rgba(255,255,255,0.12);
}
.flash-success { background: rgba(34,197,94,0.14); border-color: rgba(34,197,94,0.3); color: #86efac; }
.flash-error { background: rgba(239,68,68,0.14); border-color: rgba(239,68,68,0.3); color: #fca5a5; }
.input, select.input {
  width: 100%;
  background: rgba(255,255,255,0.07);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 12px;
  color: white;
  padding: 12px 14px;
  font-family: 'Outfit', sans-serif;
  font-size: 14px;
}
.input::placeholder { color: rgba(255,255,255,0.3); }
.input:focus {
  outline: none;
  border-color: rgba(124,108,240,0.7);
  background: rgba(124,108,240,0.12);
}
select.input option { background: #1d1635; color: white; }
.row {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 14px;
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  margin-bottom: 8px;
}
.row .name { flex: 1; font-weight: 600; font-size: 14px; }
.row .meta { font-size: 12px; color: rgba(255,255,255,0.5); }
.inline-form { display: flex; gap: 8px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
.inline-form .input { flex: 1; min-width: 160px; }
.empty {
  padding: 24px; text-align: center; color: rgba(255,255,255,0.4); font-size: 13px;
  border: 1px dashed rgba(255,255,255,0.12); border-radius: 14px;
}
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.badge-admin { background: rgba(168,85,247,0.2); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.4); }
.badge-operator { background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }
.cat-section { margin-bottom: 18px; }
.cat-title {
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.8px;
  color: rgba(255,255,255,0.5); font-weight: 700; margin-bottom: 8px; padding-left: 4px;
}
.count-pill {
  display: inline-block; padding: 4px 12px; border-radius: 999px;
  background: rgba(124,108,240,0.15); border: 1px solid rgba(124,108,240,0.3);
  color: #c4b5fd; font-size: 12px; font-weight: 600;
}
.search-bar { margin-bottom: 14px; }
/* Bottom-sheet modal */
.modal-backdrop {
  display: none;
  position: fixed; inset: 0; background: rgba(0,0,0,0.55);
  z-index: 50; backdrop-filter: blur(4px);
  align-items: flex-end; justify-content: center;
}
.modal-backdrop.open { display: flex; animation: fadeIn 0.2s; }
.modal {
  background: rgba(29,22,53,0.98);
  backdrop-filter: blur(24px);
  border-top: 1px solid rgba(255,255,255,0.12);
  border-radius: 24px 24px 0 0;
  width: 100%; max-width: 540px;
  padding: 22px 22px 28px;
  max-height: 88vh; overflow-y: auto;
  animation: slideUp 0.25s ease-out;
}
@keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
.modal h3 { margin-bottom: 14px; font-size: 18px; }
.form-group { margin-bottom: 12px; }
.form-group label {
  display: block; margin-bottom: 6px; font-weight: 600;
  color: rgba(255,255,255,0.55); font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.8px;
}
.norms-table-wrap { overflow-x: auto; border-radius: 14px; }
.norms-table { width: 100%; border-collapse: separate; border-spacing: 0; min-width: 500px; }
.norms-table th, .norms-table td {
  padding: 10px 12px; text-align: left; font-size: 13px;
  border-bottom: 1px solid rgba(255,255,255,0.07);
}
.norms-table th {
  background: rgba(124,108,240,0.12);
  color: rgba(255,255,255,0.8); font-weight: 600;
  white-space: nowrap; position: sticky; top: 0;
}
.norms-table input {
  width: 72px;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  color: white;
  padding: 6px 8px;
  border-radius: 8px;
  font-family: inherit;
  font-size: 13px;
  text-align: center;
}
.norms-table input:focus { outline: none; border-color: rgba(124,108,240,0.7); }
.tip {
  background: rgba(124,108,240,0.1);
  border: 1px solid rgba(124,108,240,0.25);
  border-radius: 12px;
  padding: 10px 14px;
  font-size: 13px;
  color: rgba(255,255,255,0.75);
  margin-bottom: 14px;
}
.preset-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px; margin-top: 10px;
}
.preset-btn {
  padding: 16px 12px; border-radius: 16px;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  color: white; font-weight: 600; font-size: 14px;
  cursor: pointer; text-align: center;
  transition: all 0.15s;
}
.preset-btn:hover {
  background: rgba(124,108,240,0.2);
  border-color: rgba(124,108,240,0.5);
  transform: translateY(-2px);
}
.drop-zone {
  border: 2px dashed rgba(255,255,255,0.18);
  border-radius: 14px;
  padding: 20px;
  text-align: center;
  color: rgba(255,255,255,0.6);
  font-size: 13px;
  margin-top: 10px;
}
.import-result {
  margin-top: 12px; padding: 12px 14px;
  border-radius: 12px; font-size: 13px;
  background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.25);
  color: #86efac;
}
.import-result.err { background: rgba(239,68,68,0.1); border-color: rgba(239,68,68,0.25); color: #fca5a5; }
.pwd-box {
  background: rgba(250,204,21,0.1);
  border: 1px solid rgba(250,204,21,0.3);
  color: #fde68a;
  padding: 14px;
  border-radius: 12px;
  margin-bottom: 14px;
  font-size: 13px;
}
.pwd-box code { background: rgba(0,0,0,0.3); padding: 3px 8px; border-radius: 6px; font-size: 14px; }
.row-actions { display: flex; gap: 6px; }
hr.soft { border: 0; border-top: 1px solid rgba(255,255,255,0.08); margin: 14px 0; }
@media (max-width: 600px) {
  .header { padding: 12px 14px; }
  .header .brand .name { font-size: 15px; max-width: 180px; }
  .btn { padding: 8px 10px; font-size: 12px; }
}
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>

<div class="header">
  <div class="brand">
    <div class="name">👨‍💼 {{ org.name }}</div>
    <div class="sub">Админ панель</div>
  </div>
  <div class="actions">
    <a class="btn" href="/revision">📊 Ревизия</a>
    <a class="btn btn-danger" href="/logout">Выйти</a>
  </div>
</div>

<div class="tabs-wrap">
  <div class="tabs" id="tabs">
    <div class="tab-pill active" data-tab="tab-locations" onclick="switchTab('tab-locations')">📍 Локации</div>
    <div class="tab-pill" data-tab="tab-categories" onclick="switchTab('tab-categories')">🗂 Категории</div>
    <div class="tab-pill" data-tab="tab-products" onclick="switchTab('tab-products')">📦 Товары</div>
    <div class="tab-pill" data-tab="tab-users" onclick="switchTab('tab-users')">👥 Пользователи</div>
    <div class="tab-pill" data-tab="tab-norms" onclick="switchTab('tab-norms')">📏 Нормы</div>
    <div class="tab-pill" data-tab="tab-import" onclick="switchTab('tab-import')">📥 Импорт</div>
    <div class="tab-pill" data-tab="tab-requests" onclick="switchTab('tab-requests')">📨 Запросы{% if pending_revs %} <span style="background:#ef4444;color:white;padding:1px 7px;border-radius:999px;font-size:10px;margin-left:4px;">{{ pending_revs|length }}</span>{% endif %}</div>
    <div class="tab-pill" data-tab="tab-history" onclick="switchTab('tab-history')">🗂 История</div>
  </div>
</div>

<div class="container">

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, msg in messages %}
      <div class="flash-box {% if category == 'error' %}flash-error{% else %}flash-success{% endif %}">{{ msg }}</div>
    {% endfor %}
  {% endwith %}

  {% if new_user_pwd %}
  <div class="pwd-box">
    🔑 Пароль для <b>{{ new_user_name }}</b>: <code>{{ new_user_pwd }}</code>
    — сохраните его сейчас, повторно показан не будет.
  </div>
  {% endif %}

  <!-- Tab: Локации -->
  <div class="tab-content active" id="tab-locations">
    <div class="card">
      <h2>Локации <span class="count-pill">{{ locations|length }}</span></h2>
      {% if locations %}
        {% for loc in locations %}
        <div class="row">
          <div class="name">📍 {{ loc.name }}</div>
          <form method="post" action="/admin/locations/delete/{{ loc.id }}" onsubmit="return confirm('Удалить локацию «{{ loc.name }}»? Нормы и ревизии на этой локации будут удалены.');">
            <button class="btn btn-danger btn-small" type="submit">Удалить</button>
          </form>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">Пока нет локаций</div>
      {% endif %}
      <hr class="soft">
      <form method="post" action="/admin/locations/add" class="inline-form">
        <input class="input" type="text" name="name" placeholder="Название локации" required maxlength="100">
        <button class="btn btn-primary" type="submit">+ Добавить</button>
      </form>
    </div>
  </div>

  <!-- Tab: Категории -->
  <div class="tab-content" id="tab-categories">
    <div class="card">
      <h2>Категории <span class="count-pill">{{ categories|length }}</span></h2>
      {% if categories %}
        {% for cat in categories %}
        <div class="row">
          <div class="name">🗂 {{ cat.name }}</div>
          <form method="post" action="/admin/categories/delete/{{ cat.id }}" onsubmit="return confirm('Удалить категорию «{{ cat.name }}»?');">
            <button class="btn btn-danger btn-small" type="submit">Удалить</button>
          </form>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">Пока нет категорий</div>
      {% endif %}
      <hr class="soft">
      <form method="post" action="/admin/categories/add" class="inline-form">
        <input class="input" type="text" name="name" placeholder="Название категории" required maxlength="200">
        <button class="btn btn-primary" type="submit">+ Добавить</button>
      </form>
    </div>
  </div>

  <!-- Tab: Товары -->
  <div class="tab-content" id="tab-products">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;">
        <h2 style="margin:0;">Товары <span class="count-pill">Всего: {{ products|length }}</span></h2>
        <button class="btn btn-primary" onclick="openModal('modal-add-product')">+ Добавить товар</button>
      </div>
      <div class="search-bar">
        <input class="input" id="product-search" type="text" placeholder="🔎 Поиск по названию или коду" oninput="filterProducts()">
      </div>
      {% if products %}
        {% set uncat = grouped.get(None, []) %}
        {% for cat in categories %}
          {% set items = grouped.get(cat.id, []) %}
          {% if items %}
          <div class="cat-section" data-cat="{{ cat.name }}">
            <div class="cat-title">{{ cat.name }} · {{ items|length }}</div>
            {% for p in items %}
            <div class="row product-row" data-name="{{ p.name|lower }}" data-code="{{ (p.code or '')|lower }}">
              <div style="flex:1;">
                <div class="name">{{ p.name }}</div>
                <div class="meta">{{ p.code or '—' }} · {{ p.unit }}</div>
              </div>
              <div class="row-actions">
                <button class="btn btn-small" onclick='openEditProduct({{ p.id }}, {{ p.name|tojson }}, {{ (p.code or "")|tojson }}, {{ p.unit|tojson }}, {{ (p.category_id or 0) }})'>✎</button>
                <form method="post" action="/admin/products/delete/{{ p.id }}" onsubmit="return confirm('Удалить «{{ p.name }}»?');" style="display:inline;">
                  <button class="btn btn-danger btn-small" type="submit">×</button>
                </form>
              </div>
            </div>
            {% endfor %}
          </div>
          {% endif %}
        {% endfor %}
        {% if uncat %}
        <div class="cat-section" data-cat="без категории">
          <div class="cat-title">Без категории · {{ uncat|length }}</div>
          {% for p in uncat %}
          <div class="row product-row" data-name="{{ p.name|lower }}" data-code="{{ (p.code or '')|lower }}">
            <div style="flex:1;">
              <div class="name">{{ p.name }}</div>
              <div class="meta">{{ p.code or '—' }} · {{ p.unit }}</div>
            </div>
            <div class="row-actions">
              <button class="btn btn-small" onclick='openEditProduct({{ p.id }}, {{ p.name|tojson }}, {{ (p.code or "")|tojson }}, {{ p.unit|tojson }}, 0)'>✎</button>
              <form method="post" action="/admin/products/delete/{{ p.id }}" onsubmit="return confirm('Удалить «{{ p.name }}»?');" style="display:inline;">
                <button class="btn btn-danger btn-small" type="submit">×</button>
              </form>
            </div>
          </div>
          {% endfor %}
        </div>
        {% endif %}
      {% else %}
        <div class="empty">Пока нет товаров. Нажмите «+ Добавить товар» или используйте импорт.</div>
      {% endif %}
    </div>
  </div>

  <!-- Tab: Пользователи -->
  <div class="tab-content" id="tab-users">
    <div class="card">
      <h2>Пользователи <span class="count-pill">{{ users|length }}{% if org.plan == 'free' %} / {{ free_max_users }}{% endif %}</span></h2>
      {% if user_limit_reached %}
      <div class="flash-box flash-error">
        Достигнут лимит пользователей тарифа FREE ({{ free_max_users }}). Обновите тариф, чтобы добавлять больше.
      </div>
      {% endif %}
      {% for u in users %}
      <div class="row">
        <div style="flex:1;">
          <div class="name">{{ u.username }}
            <span class="badge {% if u.role == 'admin' %}badge-admin{% else %}badge-operator{% endif %}">{{ u.role }}</span>
          </div>
          <div class="meta">{{ u.email or '—' }}</div>
        </div>
        {% if u.id != current_user_id %}
        <form method="post" action="/admin/users/delete/{{ u.id }}" onsubmit="return confirm('Удалить «{{ u.username }}»?');">
          <button class="btn btn-danger btn-small" type="submit">Удалить</button>
        </form>
        {% else %}
        <span class="meta">это вы</span>
        {% endif %}
      </div>
      {% endfor %}
      <hr class="soft">
      <h3>Добавить оператора</h3>
      <form method="post" action="/admin/users/add">
        <div class="form-group">
          <label>Логин*</label>
          <input class="input" type="text" name="username" required maxlength="100" placeholder="operator1">
        </div>
        <div class="form-group">
          <label>Email (опционально)</label>
          <input class="input" type="email" name="email" placeholder="worker@example.com">
        </div>
        <div class="form-group">
          <label>Пароль (опционально — сгенерируется автоматически)</label>
          <input class="input" type="text" name="password" placeholder="Оставьте пустым для автогенерации">
        </div>
        <button class="btn btn-primary" type="submit" {% if user_limit_reached %}disabled{% endif %}>Создать</button>
      </form>
    </div>
  </div>

  <!-- Tab: Нормы -->
  <div class="tab-content" id="tab-norms">
    <div class="card">
      <h2>Нормы</h2>
      <div class="tip">💡 Нормы — сколько каждого товара должно быть на каждой локации. Используется для подсветки дефицита в ревизии.</div>
      {% if products and locations %}
      <div class="norms-table-wrap">
        <table class="norms-table" id="norms-table">
          <thead>
            <tr>
              <th>Товар</th>
              {% for loc in locations %}<th>{{ loc.name }}</th>{% endfor %}
            </tr>
          </thead>
          <tbody>
            {% for p in products %}
            <tr>
              <td><b>{{ p.name }}</b> <span class="meta" style="font-size:11px;color:rgba(255,255,255,0.4);">({{ p.unit }})</span></td>
              {% for loc in locations %}
              <td>
                <input type="number" step="any" min="0"
                       data-pid="{{ p.id }}" data-lid="{{ loc.id }}"
                       value="{{ norms_map.get((p.id, loc.id), 0) }}">
              </td>
              {% endfor %}
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      <div style="margin-top:14px;display:flex;gap:10px;align-items:center;">
        <button class="btn btn-primary" onclick="saveNorms()">💾 Сохранить нормы</button>
        <span id="norms-status" class="meta"></span>
      </div>
      {% else %}
      <div class="empty">Сначала добавьте товары и локации.</div>
      {% endif %}
    </div>
  </div>

  <!-- Tab: Импорт -->
  <div class="tab-content" id="tab-import">
    <div class="card">
      <h2>Импорт товаров</h2>
      <h3>1. Скачайте шаблон</h3>
      <p class="meta" style="margin-bottom:10px;">Excel с колонками: Категория, Название, Код, Ед. изм.</p>
      <a class="btn" href="/admin/import/template">📥 Скачать шаблон .xlsx</a>

      <hr class="soft">
      <h3>2. Загрузите заполненный файл</h3>
      <form id="import-form" onsubmit="return uploadImport(event)">
        <div class="drop-zone">
          <input type="file" name="file" accept=".xlsx,.csv" required style="color:white;">
        </div>
        <button class="btn btn-primary" type="submit" style="margin-top:12px;">📤 Загрузить</button>
      </form>
      <div id="import-result"></div>
    </div>

    <div class="card">
      <h2>🎯 Быстрый старт — готовые наборы</h2>
      <p class="meta" style="margin-bottom:10px;">Загрузите типовые товары одной кнопкой.</p>
      <div class="preset-grid">
        <form method="post" action="/admin/import/preset/burger" onsubmit="return confirm('Добавить товары набора «Бургерная»?');">
          <button class="preset-btn" type="submit" style="width:100%;">🍔 Бургерная</button>
        </form>
        <form method="post" action="/admin/import/preset/coffee" onsubmit="return confirm('Добавить товары набора «Кофейня»?');">
          <button class="preset-btn" type="submit" style="width:100%;">☕ Кофейня</button>
        </form>
        <form method="post" action="/admin/import/preset/bakery" onsubmit="return confirm('Добавить товары набора «Пекарня»?');">
          <button class="preset-btn" type="submit" style="width:100%;">🥐 Пекарня</button>
        </form>
        <form method="post" action="/admin/import/preset/sushi" onsubmit="return confirm('Добавить товары набора «Суши»?');">
          <button class="preset-btn" type="submit" style="width:100%;">🍣 Суши</button>
        </form>
      </div>
    </div>
  </div>

  <!-- Tab: Запросы -->
  <div class="tab-content" id="tab-requests">
    <div class="card">
      <h2>Запросы на подтверждение <span class="count-pill">{{ pending_revs|length }}</span></h2>
      <div class="tip">💡 Оператор отправил завершённую ревизию на проверку. Подтвердите — и xlsx-отчёт скачается автоматически.</div>
      {% if pending_revs %}
        {% for r in pending_revs %}
        <div class="row" style="flex-wrap:wrap;gap:10px;">
          <div style="flex:1;min-width:200px;">
            <div class="name">📍 {{ r.location }}</div>
            <div class="meta">Оператор: {{ r.user }} · {{ r.created_at }} · позиций: {{ r.items_count }}</div>
          </div>
          <div class="row-actions" style="gap:8px;">
            <form method="post" action="/admin/revisions/confirm/{{ r.id }}" style="display:inline;">
              <button class="btn btn-primary btn-small" type="submit">✅ Подтвердить</button>
            </form>
            <form method="post" action="/admin/revisions/reject/{{ r.id }}" onsubmit="return confirm('Отклонить ревизию? Она будет отменена.');" style="display:inline;">
              <button class="btn btn-danger btn-small" type="submit">❌ Отклонить</button>
            </form>
          </div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">Нет ожидающих запросов</div>
      {% endif %}
    </div>
  </div>

  <!-- Tab: История -->
  <div class="tab-content" id="tab-history">
    <div class="card">
      <h2>История ревизий <span class="count-pill">{{ completed_revs|length }}</span></h2>
      {% if completed_revs %}
        {% for r in completed_revs %}
        <div class="row" style="flex-wrap:wrap;gap:10px;">
          <div style="flex:1;min-width:200px;">
            <div class="name">📍 {{ r.location }}</div>
            <div class="meta">{{ r.user }} · {{ r.finished_at or r.created_at }} · позиций: {{ r.items_count }}</div>
          </div>
          <div class="row-actions">
            <a class="btn btn-small" href="/admin/revisions/{{ r.id }}/download">📥 Скачать</a>
          </div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">Нет завершённых ревизий</div>
      {% endif %}
    </div>
  </div>

</div>

<!-- Modal: Добавить товар -->
<div class="modal-backdrop" id="modal-add-product" onclick="if(event.target===this) closeModal('modal-add-product')">
  <div class="modal">
    <h3>Новый товар</h3>
    <form method="post" action="/admin/products/add">
      <div class="form-group">
        <label>Название*</label>
        <input class="input" name="name" required maxlength="300" placeholder="Кола 0.5л">
      </div>
      <div class="form-group">
        <label>Категория</label>
        <select class="input" name="category_id" id="add-prod-cat" onchange="toggleNewCat(this)">
          <option value="">— без категории —</option>
          {% for c in categories %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}
          <option value="__new__">+ Новая категория…</option>
        </select>
      </div>
      <div class="form-group" id="new-cat-wrap" style="display:none;">
        <label>Название новой категории</label>
        <input class="input" name="new_category" maxlength="200" placeholder="Например: Напитки">
      </div>
      <div class="form-group">
        <label>Единица измерения</label>
        <input class="input" name="unit" value="шт" maxlength="20">
      </div>
      <div class="form-group">
        <label>Код</label>
        <input class="input" name="code" maxlength="100" placeholder="оставьте пустым для автогенерации">
      </div>
      <div style="display:flex;gap:10px;margin-top:6px;">
        <button type="button" class="btn" style="flex:1;" onclick="closeModal('modal-add-product')">Отмена</button>
        <button class="btn btn-primary" type="submit" style="flex:1;">Добавить</button>
      </div>
    </form>
  </div>
</div>

<!-- Modal: Редактировать товар -->
<div class="modal-backdrop" id="modal-edit-product" onclick="if(event.target===this) closeModal('modal-edit-product')">
  <div class="modal">
    <h3>Редактировать товар</h3>
    <form method="post" id="edit-prod-form">
      <div class="form-group">
        <label>Название*</label>
        <input class="input" name="name" id="edit-name" required maxlength="300">
      </div>
      <div class="form-group">
        <label>Категория</label>
        <select class="input" name="category_id" id="edit-cat">
          <option value="">— без категории —</option>
          {% for c in categories %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}
        </select>
      </div>
      <div class="form-group">
        <label>Единица измерения</label>
        <input class="input" name="unit" id="edit-unit" maxlength="20">
      </div>
      <div class="form-group">
        <label>Код</label>
        <input class="input" name="code" id="edit-code" maxlength="100">
      </div>
      <div style="display:flex;gap:10px;margin-top:6px;">
        <button type="button" class="btn" style="flex:1;" onclick="closeModal('modal-edit-product')">Отмена</button>
        <button class="btn btn-primary" type="submit" style="flex:1;">Сохранить</button>
      </div>
    </form>
  </div>
</div>

<script>
function switchTab(id) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-pill').forEach(el => el.classList.remove('active'));
  const content = document.getElementById(id);
  if (content) content.classList.add('active');
  const pill = document.querySelector('.tab-pill[data-tab="' + id + '"]');
  if (pill) {
    pill.classList.add('active');
    pill.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  }
  if (history.replaceState) history.replaceState(null, '', '#' + id);
}
if (window.location.hash) {
  const id = window.location.hash.substring(1);
  if (document.getElementById(id)) switchTab(id);
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function toggleNewCat(sel) {
  document.getElementById('new-cat-wrap').style.display = (sel.value === '__new__') ? 'block' : 'none';
  if (sel.value === '__new__') sel.name = '_ignore'; else sel.name = 'category_id';
}

function openEditProduct(id, name, code, unit, catId) {
  document.getElementById('edit-prod-form').action = '/admin/products/edit/' + id;
  document.getElementById('edit-name').value = name;
  document.getElementById('edit-code').value = code;
  document.getElementById('edit-unit').value = unit;
  document.getElementById('edit-cat').value = catId ? String(catId) : '';
  openModal('modal-edit-product');
}

function filterProducts() {
  const q = (document.getElementById('product-search').value || '').toLowerCase().trim();
  document.querySelectorAll('.product-row').forEach(r => {
    const n = r.dataset.name || '';
    const c = r.dataset.code || '';
    r.style.display = (!q || n.includes(q) || c.includes(q)) ? '' : 'none';
  });
  document.querySelectorAll('.cat-section').forEach(s => {
    const visible = Array.from(s.querySelectorAll('.product-row')).some(r => r.style.display !== 'none');
    s.style.display = visible ? '' : 'none';
  });
}

async function saveNorms() {
  const status = document.getElementById('norms-status');
  status.textContent = 'Сохранение…';
  const payload = {};
  document.querySelectorAll('#norms-table input').forEach(inp => {
    const pid = inp.dataset.pid, lid = inp.dataset.lid;
    if (!payload[pid]) payload[pid] = {};
    payload[pid][lid] = parseFloat(inp.value || '0') || 0;
  });
  try {
    const res = await fetch('/admin/norms/save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.ok) status.textContent = '✔ Сохранено (' + data.saved + ' изменений)';
    else status.textContent = '✖ ' + (data.error || 'ошибка');
  } catch (e) {
    status.textContent = '✖ ' + e;
  }
}

async function uploadImport(ev) {
  ev.preventDefault();
  const form = document.getElementById('import-form');
  const fd = new FormData(form);
  const box = document.getElementById('import-result');
  box.className = '';
  box.textContent = 'Загрузка…';
  try {
    const res = await fetch('/admin/import/upload', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.ok) {
      box.className = 'import-result';
      let html = 'Добавлено ' + data.added + ' товаров. Пропущено ' + data.skipped + '.';
      if (data.errors && data.errors.length) {
        html += '<br><small style="opacity:0.8">' + data.errors.slice(0, 8).join('<br>') + '</small>';
      }
      box.innerHTML = html;
      setTimeout(() => window.location.href = '/admin#tab-products', 1500);
    } else {
      box.className = 'import-result err';
      box.textContent = '✖ ' + (data.error || 'ошибка');
    }
  } catch (e) {
    box.className = 'import-result err';
    box.textContent = '✖ ' + e;
  }
  return false;
}
</script>
</body>
</html>'''


revision_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Ревизия — {{ org.name }}</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;}
body{font-family:'Outfit',sans-serif;background:linear-gradient(135deg,#13111C 0%,#1d1635 50%,#231b50 100%);background-attachment:fixed;min-height:100vh;color:#fff;padding-bottom:90px;}
header{background:rgba(255,255,255,0.05);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(255,255,255,0.08);padding:14px 20px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100;}
header h1{font-size:18px;font-weight:700;background:linear-gradient(135deg,#7c6cf0,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
header p{font-size:12px;color:rgba(255,255,255,0.4);margin-top:2px;}
.hbtns{display:flex;gap:8px;}
.hbtn{padding:8px 12px;border:none;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;font-family:'Outfit',sans-serif;text-decoration:none;display:inline-block;}
.hbtn-outline{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);color:rgba(255,255,255,0.8);}
.hbtn-primary{background:linear-gradient(135deg,#7c6cf0,#a855f7);color:#fff;box-shadow:0 4px 15px rgba(124,108,240,0.3);}
.tabs{display:flex;overflow-x:auto;padding:14px 20px;gap:10px;scrollbar-width:none;}
.tabs::-webkit-scrollbar{display:none;}
.tab{padding:8px 18px;border-radius:50px;font-weight:600;color:rgba(255,255,255,0.5);text-decoration:none;white-space:nowrap;font-size:14px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);transition:all 0.2s;}
.tab.active{background:linear-gradient(135deg,rgba(124,108,240,0.5),rgba(168,85,247,0.4));border-color:rgba(124,108,240,0.5);color:#fff;box-shadow:0 4px 15px rgba(124,108,240,0.25);}
.container{padding:0 16px;}
.search-wrap{position:sticky;top:60px;z-index:90;background:transparent;padding:10px 0;}
.search-input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.1);border-radius:14px;color:#fff;font-size:15px;font-family:'Outfit',sans-serif;}
.search-input::placeholder{color:rgba(255,255,255,0.3);}
.search-input:focus{outline:none;border-color:rgba(124,108,240,0.6);}
.cat-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.4);margin:18px 0 8px;}
.product-item{background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:14px 16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:all 0.15s;}
.product-item:active{transform:scale(0.98);}
.product-item:hover{background:rgba(255,255,255,0.1);}
.p-name{font-weight:500;font-size:15px;color:#fff;}
.p-meta{font-size:12px;color:rgba(255,255,255,0.4);margin-top:3px;}
.badge{padding:5px 10px;border-radius:8px;font-size:13px;font-weight:700;min-width:36px;text-align:center;}
.badge-neutral{background:rgba(124,108,240,0.3);color:#a5b4fc;}
.badge-green{background:rgba(16,185,129,0.25);color:#6ee7b7;}
.badge-yellow{background:rgba(251,191,36,0.25);color:#fcd34d;}
.badge-red{background:rgba(239,68,68,0.25);color:#fca5a5;}
.empty-msg{text-align:center;color:rgba(255,255,255,0.35);padding:40px 20px;font-size:14px;}
.finish-btn{position:fixed;bottom:20px;left:20px;right:20px;background:linear-gradient(135deg,#7c6cf0,#a855f7);color:#fff;border:none;padding:16px;border-radius:16px;font-size:16px;font-weight:700;cursor:pointer;font-family:'Outfit',sans-serif;box-shadow:0 8px 24px rgba(124,108,240,0.45);z-index:90;}
.finish-btn:disabled{opacity:0.5;cursor:not-allowed;}
/* Modal */
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,8,20,0.7);backdrop-filter:blur(6px);z-index:1000;align-items:flex-end;}
.modal.active{display:flex;animation:fadein 0.2s;}
@keyframes fadein{from{opacity:0;}to{opacity:1;}}
.modal-sheet{background:rgba(20,16,38,0.97);border:1px solid rgba(255,255,255,0.1);width:100%;border-radius:24px 24px 0 0;padding:24px;box-shadow:0 -10px 40px rgba(0,0,0,0.5);animation:slideup 0.3s cubic-bezier(0.16,1,0.3,1);}
@keyframes slideup{from{transform:translateY(100%);}to{transform:translateY(0);}}
.modal-center{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,8,20,0.7);backdrop-filter:blur(6px);z-index:1000;align-items:center;justify-content:center;padding:24px;}
.modal-center.active{display:flex;}
.modal-box{background:rgba(20,16,38,0.97);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:32px 24px;width:100%;max-width:360px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,0.6);animation:popIn 0.3s cubic-bezier(0.16,1,0.3,1);}
@keyframes popIn{from{opacity:0;transform:scale(0.9);}to{opacity:1;transform:scale(1);}}
.modal-box h2{color:#fff;font-size:20px;margin-bottom:8px;}
.modal-box p{color:rgba(255,255,255,0.5);font-size:14px;margin-bottom:24px;}
.modal-box .icon{font-size:42px;margin-bottom:12px;}
.modal-btns{display:flex;gap:10px;}
.mbtn{flex:1;padding:13px;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;font-family:'Outfit',sans-serif;border:none;}
.mbtn-no{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);color:rgba(255,255,255,0.7);}
.mbtn-yes{background:linear-gradient(135deg,#7c6cf0,#a855f7);color:#fff;box-shadow:0 4px 15px rgba(124,108,240,0.4);}
.mbtn-ok{width:100%;background:linear-gradient(135deg,#7c6cf0,#a855f7);color:#fff;box-shadow:0 4px 15px rgba(124,108,240,0.4);}
/* Calculator */
.calc-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;}
.calc-title{font-size:16px;font-weight:700;color:#fff;max-width:80%;}
.calc-close{background:rgba(255,255,255,0.1);border:none;color:#fff;width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:16px;}
.calc-display{width:100%;font-size:30px;padding:10px 4px;text-align:right;border:none;border-bottom:2px solid rgba(255,255,255,0.1);color:#a5b4fc;background:transparent;font-family:'Outfit',monospace;margin-bottom:16px;}
.calc-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
.cbtn{padding:14px;border-radius:12px;border:none;font-size:18px;font-weight:500;cursor:pointer;font-family:'Outfit',sans-serif;touch-action:manipulation;}
.cbtn-num{background:rgba(255,255,255,0.08);color:#fff;}
.cbtn-num:active{background:rgba(255,255,255,0.15);}
.cbtn-op{background:rgba(124,108,240,0.2);color:#a5b4fc;}
.cbtn-op:active{background:rgba(124,108,240,0.35);}
.cbtn-save{grid-column:span 2;background:linear-gradient(135deg,#7c6cf0,#a855f7);color:#fff;font-weight:700;font-size:15px;box-shadow:0 4px 15px rgba(124,108,240,0.4);}
.total-row{margin-top:12px;text-align:center;font-size:14px;color:rgba(255,255,255,0.5);}
.total-num{color:#a5b4fc;font-weight:700;}
.values-list{margin:10px 0;max-height:90px;overflow-y:auto;border:1px solid rgba(255,255,255,0.08);border-radius:10px;background:rgba(255,255,255,0.04);display:none;}
.val-item{display:flex;justify-content:space-between;align-items:center;padding:7px 12px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:13px;color:rgba(255,255,255,0.8);}
.val-item:last-child{border-bottom:none;}
.del-val{background:none;border:none;color:rgba(239,68,68,0.7);cursor:pointer;font-size:16px;padding:0 4px;}
.hist-log{margin-top:12px;border-top:1px solid rgba(255,255,255,0.08);padding-top:10px;}
.hist-label{font-size:11px;color:rgba(255,255,255,0.35);margin-bottom:6px;}
.hist-scroll{max-height:80px;overflow-y:auto;}
.hist-item{display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:11px;color:rgba(255,255,255,0.5);}
.hist-item:last-child{border-bottom:none;}
.hist-del{background:none;border:none;color:rgba(239,68,68,0.6);cursor:pointer;font-size:14px;padding:0 4px;}
</style>
</head>
<body>
<header>
  <div>
    <h1>📊 {{ org.name }}</h1>
    <p>Ревизия · {{ username }}</p>
  </div>
  <div class="hbtns">
    {% if is_admin %}<a href="/admin" class="hbtn hbtn-outline">⚙️ Админ</a>{% endif %}
    <a href="/logout" class="hbtn hbtn-outline">Выйти</a>
  </div>
</header>

{% if not locations %}
  <div class="empty-msg">🏠 Нет локаций.<br>Попросите администратора добавить локации.</div>
{% else %}
<div class="tabs">
  {% for loc in locations %}
  <a href="/revision?location={{ loc.name|urlencode }}" class="tab {% if selected and selected.id == loc.id %}active{% endif %}">{{ loc.name }}</a>
  {% endfor %}
</div>

{% if selected %}
<div class="container">
  <div class="search-wrap">
    <input id="search" class="search-input" type="text" placeholder="🔍 Поиск товара..." oninput="filterProducts()">
  </div>

  {% if not grouped %}
    <div class="empty-msg">📦 Нет товаров.<br>Добавьте товары в админ-панели.</div>
  {% else %}
  <div id="productList">
  {% for cat, prods in grouped %}
    <div class="product-group">
      <div class="cat-label">{{ cat.name if cat else 'Без категории' }}</div>
      {% for p in prods %}
        {% set qty = qty_map.get(p.id, 0) %}
        {% set norm = norms_map.get(p.id) %}
        {% if norm and norm > 0 %}
          {% if qty >= norm %}
            {% set badge_cls = 'badge-green' %}
          {% elif qty >= norm * 0.5 %}
            {% set badge_cls = 'badge-yellow' %}
          {% else %}
            {% set badge_cls = 'badge-red' %}
          {% endif %}
          {% set badge_text = qty|string + ' / ' + norm|int|string %}
        {% else %}
          {% set badge_cls = 'badge-neutral' %}
          {% set badge_text = qty|string if qty > 0 else '' %}
        {% endif %}
        <div class="product-item" data-name="{{ p.name|lower }}"
          onclick="openCalc({{ p.id }}, {{ selected.id }}, '{{ p.name|replace("'","\\'")|e }}', '{{ p.unit }}')">
          <div>
            <div class="p-name">{{ p.name }}</div>
            <div class="p-meta">{{ p.unit }}{% if norm and norm > 0 %} · норма {{ norm|int }}{% endif %}</div>
          </div>
          {% if qty > 0 or (norm and norm > 0) %}
          <div class="badge {{ badge_cls }}">{{ badge_text if badge_text else '0' }}</div>
          {% endif %}
        </div>
      {% endfor %}
    </div>
  {% endfor %}
  </div>
  {% endif %}
</div>

{% if rev_status == 'pending' %}
  <button class="finish-btn" disabled>⏳ Ожидание подтверждения...</button>
{% else %}
  <button class="finish-btn" onclick="requestFinish()">Завершить ревизию</button>
{% endif %}
{% endif %}
{% endif %}

<!-- Calculator modal -->
<div class="modal" id="calcModal" onclick="if(event.target===this)closeCalc()">
<div class="modal-sheet">
  <div class="calc-header">
    <div class="calc-title" id="calcTitle"></div>
    <button class="calc-close" onclick="closeCalc()">✕</button>
  </div>
  <input id="calcDisplay" class="calc-display" readonly value="0">
  <div class="calc-grid">
    <button class="cbtn cbtn-num" onclick="num('7')">7</button>
    <button class="cbtn cbtn-num" onclick="num('8')">8</button>
    <button class="cbtn cbtn-num" onclick="num('9')">9</button>
    <button class="cbtn cbtn-op" onclick="setOp('/')">÷</button>
    <button class="cbtn cbtn-num" onclick="num('4')">4</button>
    <button class="cbtn cbtn-num" onclick="num('5')">5</button>
    <button class="cbtn cbtn-num" onclick="num('6')">6</button>
    <button class="cbtn cbtn-op" onclick="setOp('*')">×</button>
    <button class="cbtn cbtn-num" onclick="num('1')">1</button>
    <button class="cbtn cbtn-num" onclick="num('2')">2</button>
    <button class="cbtn cbtn-num" onclick="num('3')">3</button>
    <button class="cbtn cbtn-op" onclick="setOp('-')">−</button>
    <button class="cbtn cbtn-num" onclick="num('.')">.</button>
    <button class="cbtn cbtn-num" onclick="num('0')">0</button>
    <button class="cbtn cbtn-op" onclick="clr()">C</button>
    <button class="cbtn cbtn-op" onclick="setOp('+')">+</button>
    <button class="cbtn cbtn-op" onclick="calculate()">=</button>
    <button class="cbtn cbtn-op" onclick="addToTotal()">+∑</button>
    <button class="cbtn cbtn-save" onclick="saveResult()">СОХРАНИТЬ</button>
  </div>
  <div id="addedValuesList" class="values-list"></div>
  <div class="total-row">Итого: <span id="total" class="total-num">0</span> <span id="unitLabel"></span></div>
  <div class="hist-log">
    <div class="hist-label">История (текущая сессия):</div>
    <div class="hist-scroll" id="histLog"></div>
  </div>
</div>
</div>

<!-- Confirm finish modal -->
<div class="modal-center" id="confirmModal">
<div class="modal-box">
  <div class="icon">📋</div>
  <h2>Завершить ревизию?</h2>
  <p>Запрос отправится администратору на подтверждение</p>
  <div class="modal-btns">
    <button class="mbtn mbtn-no" onclick="cancelFinish()">Нет</button>
    <button class="mbtn mbtn-yes" onclick="confirmFinish()">Да</button>
  </div>
</div>
</div>

<!-- Sent modal -->
<div class="modal-center" id="sentModal">
<div class="modal-box">
  <div class="icon">✅</div>
  <h2>Запрос отправлен</h2>
  <p>Ожидайте подтверждения администратором</p>
  <button class="mbtn mbtn-ok" onclick="closeSentModal()">ОК</button>
</div>
</div>

<script>
let curProdId = null, curLocId = null, curUnit = '';
let val = '0', op = null, prev = null, total = 0, addedValues = [];

function filterProducts() {
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.product-item').forEach(el => {
    const vis = el.dataset.name.includes(q);
    el.style.display = vis ? 'flex' : 'none';
  });
  document.querySelectorAll('.product-group').forEach(g => {
    const hasVis = [...g.querySelectorAll('.product-item')].some(e => e.style.display !== 'none');
    g.style.display = hasVis ? 'block' : 'none';
  });
}

async function openCalc(prodId, locId, name, unit) {
  curProdId = prodId; curLocId = locId; curUnit = unit;
  val = '0'; op = null; prev = null; total = 0; addedValues = [];
  document.getElementById('calcTitle').innerText = name;
  document.getElementById('unitLabel').innerText = unit;
  document.getElementById('calcDisplay').value = '0';
  document.getElementById('total').innerText = '0';
  renderValuesList();
  await loadHistory(prodId, locId);
  document.getElementById('calcModal').classList.add('active');
}

async function loadHistory(prodId, locId) {
  try {
    const res = await fetch(`/revision/product_history/${prodId}?location_id=${locId}`);
    const data = await res.json();
    const el = document.getElementById('histLog');
    if (!data.length) { el.innerHTML = '<span style="color:rgba(255,255,255,0.3)">Пусто</span>'; return; }
    el.innerHTML = data.map(h =>
      `<div class="hist-item">
        <span>${h.text}</span>
        <button class="hist-del" onclick="deleteHistItem(${h.id})">×</button>
      </div>`
    ).join('');
  } catch(e) { }
}

async function deleteHistItem(itemId) {
  if (!confirm('Удалить запись?')) return;
  await fetch(`/revision/delete_item/${itemId}`, {method: 'POST'});
  await loadHistory(curProdId, curLocId);
  location.reload();
}

function closeCalc() { document.getElementById('calcModal').classList.remove('active'); }

function num(n) { if(val==='0'||val==='Error') val=n; else val+=n; document.getElementById('calcDisplay').value=val; }
function setOp(o) { prev=parseFloat(val); val='0'; op=o; }
function calculate() {
  if(op&&prev!=null){
    const cur=parseFloat(val); let r;
    switch(op){case'+':r=prev+cur;break;case'-':r=prev-cur;break;case'*':r=prev*cur;break;case'/':r=cur!==0?prev/cur:'Error';break;}
    val=r.toString(); op=null; prev=null; document.getElementById('calcDisplay').value=val;
  }
}
function clr() { val='0'; prev=null; op=null; document.getElementById('calcDisplay').value='0'; }
function addToTotal() {
  calculate();
  const n = parseFloat(val);
  if(!isNaN(n) && n !== 0) { addedValues.push(n); renderValuesList(); }
  val='0'; document.getElementById('calcDisplay').value='0';
}
function renderValuesList() {
  const list = document.getElementById('addedValuesList');
  if (!addedValues.length) { list.style.display='none'; list.innerHTML=''; total=0; }
  else {
    list.style.display='block';
    list.innerHTML = addedValues.map((v,i) =>
      `<div class="val-item"><span>${v}</span><button class="del-val" onclick="removeValue(${i})">×</button></div>`
    ).join('');
    total = Math.round(addedValues.reduce((a,b)=>a+b,0)*1000)/1000;
  }
  document.getElementById('total').innerText = total;
}
function removeValue(i) { addedValues.splice(i,1); renderValuesList(); }

async function saveResult() {
  let n = addedValues.length ? total : parseFloat(val);
  if(isNaN(n)||n<=0){alert('Введите корректное число');return;}
  const fd = new FormData();
  fd.append('product_id', curProdId);
  fd.append('location_id', curLocId);
  fd.append('count', n);
  await fetch('/revision/add', {method:'POST', body:fd});
  closeCalc();
  location.reload();
}

function requestFinish() { document.getElementById('confirmModal').classList.add('active'); }
function cancelFinish() { document.getElementById('confirmModal').classList.remove('active'); }
async function confirmFinish() {
  document.getElementById('confirmModal').classList.remove('active');
  const fd = new FormData();
  fd.append('location_id', {{ selected.id if selected else 0 }});
  await fetch('/revision/finish', {method:'POST', body:fd});
  document.getElementById('sentModal').classList.add('active');
}
function closeSentModal() { document.getElementById('sentModal').classList.remove('active'); location.reload(); }
</script>
</body>
</html>'''


# ============== СТАРЫЕ ШАБЛОНЫ (для следующих фаз миграции) ==============
# Сохранены как есть — НЕ используются до миграции /admin и /revision на БД.

legacy_login_html = '''<!-- Старый login-шаблон сохранён в истории git -->'''

legacy_revision_html = '''<!-- Старый revision-шаблон (см. git) -->'''

legacy_admin_html = '''<!-- Старый admin-шаблон (см. git) -->'''


# ============== OWNER PANEL HTML ==============

_OWNER_BASE_CSS = '''
* { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: linear-gradient(135deg, #13111C 0%, #1d1635 50%, #231b50 100%);
    background-attachment: fixed;
    min-height: 100vh;
    color: white;
}
.blob { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.35; pointer-events: none; z-index: 0; }
.blob-1 { width: 400px; height: 400px; background: radial-gradient(circle, #7c6cf0, #a855f7); top: -100px; left: -100px; }
.blob-2 { width: 350px; height: 350px; background: radial-gradient(circle, #a855f7, #6d28d9); bottom: -80px; right: -80px; }
.glass {
    background: rgba(255,255,255,0.07);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 16px;
}
.owner-header {
    position: sticky; top: 0; z-index: 100;
    background: rgba(19,17,28,0.85);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid rgba(255,255,255,0.08);
    padding: 0 24px;
    display: flex; align-items: center; justify-content: space-between;
    height: 60px;
}
.owner-header .brand { font-weight: 700; font-size: 18px; }
.owner-header .brand span { background: linear-gradient(135deg, #7c6cf0, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.owner-header .right { display: flex; align-items: center; gap: 16px; }
.owner-email { font-size: 13px; color: rgba(255,255,255,0.5); }
.btn-logout {
    background: rgba(239,68,68,0.15); color: #fca5a5;
    border: 1px solid rgba(239,68,68,0.25); border-radius: 10px;
    padding: 7px 14px; font-size: 13px; font-family: 'Outfit', sans-serif;
    cursor: pointer; text-decoration: none; font-weight: 600;
}
.btn-logout:hover { background: rgba(239,68,68,0.25); }
.owner-nav {
    display: flex; gap: 4px; padding: 16px 24px 0;
}
.nav-tab {
    padding: 9px 18px; border-radius: 12px; font-size: 14px; font-weight: 600;
    text-decoration: none; color: rgba(255,255,255,0.55);
    transition: all 0.2s;
}
.nav-tab:hover { background: rgba(255,255,255,0.07); color: white; }
.nav-tab.active {
    background: rgba(124,108,240,0.2); color: #a78bfa;
    border: 1px solid rgba(124,108,240,0.3);
}
.page-content { padding: 20px 24px 40px; max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }
.metrics-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
}
@media(max-width: 768px) { .metrics-grid { grid-template-columns: repeat(2, 1fr); } }
@media(max-width: 480px) { .metrics-grid { grid-template-columns: repeat(2, 1fr); } }
.metric-card {
    background: rgba(255,255,255,0.07);
    backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 16px; padding: 20px;
}
.metric-num { font-size: 32px; font-weight: 700; color: white; line-height: 1; }
.metric-label { font-size: 13px; color: rgba(255,255,255,0.5); margin-top: 6px; }
.section-title { font-size: 15px; font-weight: 700; margin-bottom: 12px; color: rgba(255,255,255,0.85); }
.section-card {
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 16px; padding: 20px; margin-bottom: 20px;
}
.expiring-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.06);
    font-size: 14px;
}
.expiring-row:last-child { border-bottom: none; }
.expiring-name { font-weight: 600; }
.expiring-email { color: rgba(255,255,255,0.5); font-size: 12px; }
.days-badge {
    background: rgba(251,146,60,0.2); color: #fb923c;
    border: 1px solid rgba(251,146,60,0.3);
    border-radius: 8px; padding: 2px 8px; font-size: 12px; font-weight: 600;
    margin-right: 10px;
}
.btn-sm {
    padding: 6px 12px; border-radius: 8px; font-size: 12px; font-weight: 600;
    font-family: 'Outfit', sans-serif; cursor: pointer; border: none; text-decoration: none;
    display: inline-block;
}
.btn-extend { background: rgba(124,108,240,0.25); color: #a78bfa; border: 1px solid rgba(124,108,240,0.3); }
.btn-extend:hover { background: rgba(124,108,240,0.4); }
.btn-pro { background: rgba(16,185,129,0.2); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }
.btn-pro:hover { background: rgba(16,185,129,0.35); }
.btn-free { background: rgba(100,116,139,0.2); color: #94a3b8; border: 1px solid rgba(100,116,139,0.3); }
.btn-free:hover { background: rgba(100,116,139,0.35); }
.btn-danger { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.25); }
.btn-danger:hover { background: rgba(239,68,68,0.3); }
.btn-warn { background: rgba(251,191,36,0.15); color: #fcd34d; border: 1px solid rgba(251,191,36,0.25); }
.btn-warn:hover { background: rgba(251,191,36,0.3); }
.badge {
    display: inline-block; padding: 3px 10px; border-radius: 8px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;
}
.badge-free { background: rgba(100,116,139,0.3); color: #94a3b8; }
.badge-trial { background: rgba(124,108,240,0.3); color: #a5b4fc; }
.badge-pro { background: rgba(16,185,129,0.3); color: #6ee7b7; }
.badge-business { background: rgba(251,191,36,0.3); color: #fcd34d; }
.recent-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.recent-table th {
    text-align: left; padding: 8px 12px; font-size: 11px;
    color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 0.8px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
}
.recent-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
.recent-table tr:last-child td { border-bottom: none; }
.flash-messages { position: relative; z-index: 2; padding: 12px 24px 0; }
.flash-msg {
    padding: 12px 16px; border-radius: 12px; margin-bottom: 8px; font-size: 14px; font-weight: 600;
}
.flash-success { background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }
.flash-error { background: rgba(239,68,68,0.12); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
.dot-green { background: #10b981; }
.dot-red { background: #ef4444; }
.search-box {
    width: 100%; background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.12); border-radius: 12px;
    color: white; padding: 12px 16px;
    font-family: 'Outfit', sans-serif; font-size: 14px; margin-bottom: 16px;
}
.search-box::placeholder { color: rgba(255,255,255,0.3); }
.search-box:focus { outline: none; border-color: rgba(124,108,240,0.5); background: rgba(124,108,240,0.1); }
.orgs-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.orgs-table th {
    text-align: left; padding: 10px 12px; font-size: 11px;
    color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 0.8px;
    border-bottom: 1px solid rgba(255,255,255,0.1); white-space: nowrap;
}
.orgs-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); vertical-align: middle; }
.orgs-table tr:last-child td { border-bottom: none; }
.orgs-table tr:hover td { background: rgba(255,255,255,0.03); }
.actions-cell { display: flex; gap: 4px; flex-wrap: wrap; }
@media(max-width: 900px) {
    .orgs-table { display: none; }
    .mobile-cards { display: block; }
}
@media(min-width: 901px) {
    .mobile-cards { display: none; }
}
.mobile-card {
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 16px; padding: 16px; margin-bottom: 12px;
}
.mobile-card .org-name { font-size: 15px; font-weight: 700; margin-bottom: 4px; }
.mobile-card .org-email { font-size: 12px; color: rgba(255,255,255,0.5); margin-bottom: 10px; }
.mobile-card .details { font-size: 12px; color: rgba(255,255,255,0.6); margin-bottom: 8px; display: flex; gap: 12px; flex-wrap: wrap; }
.mobile-card .actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
'''

owner_login_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Панель владельца — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _BASE_CSS + '''
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<div class="card">
  <div class="icon-box">👑</div>
  <div class="title">Панель владельца</div>
  <div class="subtitle">Вход для супер-администратора системы</div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post">
    <div class="form-group">
      <label>Email</label>
      <input class="input" type="email" name="email" required autocomplete="email" placeholder="owner@example.com">
    </div>
    <div class="form-group">
      <label>Пароль</label>
      <input class="input" type="password" name="password" required autocomplete="current-password" placeholder="Введите пароль">
    </div>
    <button class="btn-primary" type="submit">Войти →</button>
  </form>
</div>
</body>
</html>'''


owner_dashboard_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Owner Dashboard — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _OWNER_BASE_CSS + '''</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>

<header class="owner-header">
  <div class="brand">👑 <span>Панель владельца</span></div>
  <div class="right">
    <span class="owner-email">{{ owner_email }}</span>
    <a class="btn-logout" href="/owner/logout">Выйти</a>
  </div>
</header>

{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
<div class="flash-messages">
  {% for cat, msg in messages %}
  <div class="flash-msg flash-{{ cat }}">{{ msg }}</div>
  {% endfor %}
</div>
{% endif %}
{% endwith %}

<nav class="owner-nav">
  <a class="nav-tab active" href="/owner">📊 Дашборд</a>
  <a class="nav-tab" href="/owner/orgs">🏢 Компании</a>
</nav>

<div class="page-content">

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-num">{{ total_orgs }}</div>
      <div class="metric-label">Всего компаний</div>
    </div>
    <div class="metric-card">
      <div class="metric-num">{{ active_orgs }}</div>
      <div class="metric-label">Активных (7 дней)</div>
    </div>
    <div class="metric-card">
      <div class="metric-num">{{ trial_orgs }}</div>
      <div class="metric-label">На trial</div>
    </div>
    <div class="metric-card">
      <div class="metric-num">{{ paying_orgs }}</div>
      <div class="metric-label">Платящих</div>
    </div>
  </div>

  <div class="section-card">
    <div class="section-title">⚠️ Trial заканчивается скоро (3 дня)</div>
    {% if expiring_list %}
      {% for item in expiring_list %}
      <div class="expiring-row">
        <div>
          <div class="expiring-name">{{ item.name }}</div>
          <div class="expiring-email">{{ item.email }}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="days-badge">{{ item.days_left }} д.</span>
          <form method="post" action="/owner/orgs/{{ item.id }}/extend_trial" style="display:inline;">
            <button class="btn-sm btn-extend" type="submit">Продлить +7д</button>
          </form>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <div style="color:rgba(255,255,255,0.4);font-size:14px;">Нет компаний с истекающим trial.</div>
    {% endif %}
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <div class="section-card">
      <div class="section-title">🆕 Последние регистрации</div>
      <table class="recent-table">
        <thead><tr>
          <th>Компания</th><th>Email</th><th>Тариф</th><th>Дата</th>
        </tr></thead>
        <tbody>
        {% for r in recent_list %}
        <tr>
          <td style="font-weight:600;">{{ r.name }}</td>
          <td style="color:rgba(255,255,255,0.6);">{{ r.email }}</td>
          <td><span class="badge badge-{{ r.plan }}">{{ r.plan }}</span></td>
          <td style="color:rgba(255,255,255,0.5);">{{ r.created_at }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="section-card" style="display:flex;flex-direction:column;justify-content:center;align-items:center;">
      <div class="section-title" style="text-align:center;">📦 Активность сегодня</div>
      <div style="font-size:48px;font-weight:700;color:white;margin:12px 0;">{{ activity_today }}</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.5);">позиций добавлено в ревизии</div>
    </div>
  </div>

</div>
</body>
</html>'''


owner_orgs_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Компании — Owner — Spurt</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>''' + _OWNER_BASE_CSS + '''</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>

<header class="owner-header">
  <div class="brand">👑 <span>Панель владельца</span></div>
  <div class="right">
    <span class="owner-email">{{ owner_email }}</span>
    <a class="btn-logout" href="/owner/logout">Выйти</a>
  </div>
</header>

{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
<div class="flash-messages">
  {% for cat, msg in messages %}
  <div class="flash-msg flash-{{ cat }}">{{ msg }}</div>
  {% endfor %}
</div>
{% endif %}
{% endwith %}

<nav class="owner-nav">
  <a class="nav-tab" href="/owner">📊 Дашборд</a>
  <a class="nav-tab active" href="/owner/orgs">🏢 Компании</a>
</nav>

<div class="page-content">

  <input class="search-box" type="text" id="searchBox" placeholder="🔍 Поиск по названию или email..." oninput="filterOrgs(this.value)">

  <!-- Desktop table -->
  <div class="glass" style="overflow:hidden;">
  <table class="orgs-table" id="orgsTable">
    <thead><tr>
      <th>Компания</th>
      <th>Email</th>
      <th>Тариф</th>
      <th>Истекает</th>
      <th>Польз.</th>
      <th>Активность</th>
      <th>Статус</th>
      <th>Действия</th>
    </tr></thead>
    <tbody id="orgsBody">
    {% for r in org_rows %}
    <tr class="org-row" data-search="{{ r.name|lower }} {{ r.email|lower }}">
      <td style="font-weight:700;">{{ r.name }}</td>
      <td style="color:rgba(255,255,255,0.6);">{{ r.email }}</td>
      <td><span class="badge badge-{{ r.plan }}">{{ r.plan }}</span></td>
      <td style="color:rgba(255,255,255,0.5);font-size:12px;">{{ r.ends }}</td>
      <td style="text-align:center;">{{ r.user_count }}</td>
      <td style="color:rgba(255,255,255,0.5);font-size:12px;">{{ r.last_activity }}</td>
      <td>
        {% if r.is_blocked %}
          <span class="status-dot dot-red"></span>Заблокирована
        {% else %}
          <span class="status-dot dot-green"></span>Активна
        {% endif %}
      </td>
      <td>
        <div class="actions-cell">
          <form method="post" action="/owner/orgs/{{ r.id }}/extend_trial" style="display:inline;">
            <button class="btn-sm btn-extend" type="submit" title="Продлить trial +7д">+7д</button>
          </form>
          <form method="post" action="/owner/orgs/{{ r.id }}/set_plan" style="display:inline;">
            <input type="hidden" name="plan" value="pro">
            <button class="btn-sm btn-pro" type="submit" title="Установить PRO">PRO</button>
          </form>
          <form method="post" action="/owner/orgs/{{ r.id }}/set_plan" style="display:inline;">
            <input type="hidden" name="plan" value="free">
            <button class="btn-sm btn-free" type="submit" title="Установить FREE">FREE</button>
          </form>
          <form method="post" action="/owner/orgs/{{ r.id }}/toggle_block" style="display:inline;">
            <button class="btn-sm btn-warn" type="submit" title="{{ 'Разблокировать' if r.is_blocked else 'Заблокировать' }}">{{ '🔓' if r.is_blocked else '🔒' }}</button>
          </form>
          <form method="post" action="/owner/orgs/{{ r.id }}/delete" style="display:inline;"
                onsubmit="return confirm('Удалить компанию «{{ r.name }}» и ВСЕ её данные? Это действие необратимо!');">
            <button class="btn-sm btn-danger" type="submit" title="Удалить">🗑</button>
          </form>
        </div>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>

  <!-- Mobile cards -->
  <div class="mobile-cards" id="mobileCards">
  {% for r in org_rows %}
  <div class="mobile-card org-row" data-search="{{ r.name|lower }} {{ r.email|lower }}">
    <div class="org-name">{{ r.name }}</div>
    <div class="org-email">{{ r.email }}</div>
    <div class="details">
      <span><span class="badge badge-{{ r.plan }}">{{ r.plan }}</span></span>
      <span>До: {{ r.ends }}</span>
      <span>Польз.: {{ r.user_count }}</span>
    </div>
    <div style="font-size:12px;color:rgba(255,255,255,0.5);margin-bottom:6px;">
      Активность: {{ r.last_activity }} &nbsp;|&nbsp;
      {% if r.is_blocked %}
        <span class="status-dot dot-red"></span>Заблокирована
      {% else %}
        <span class="status-dot dot-green"></span>Активна
      {% endif %}
    </div>
    <div class="actions">
      <form method="post" action="/owner/orgs/{{ r.id }}/extend_trial" style="display:inline;">
        <button class="btn-sm btn-extend" type="submit">+7д trial</button>
      </form>
      <form method="post" action="/owner/orgs/{{ r.id }}/set_plan" style="display:inline;">
        <input type="hidden" name="plan" value="pro">
        <button class="btn-sm btn-pro" type="submit">PRO</button>
      </form>
      <form method="post" action="/owner/orgs/{{ r.id }}/set_plan" style="display:inline;">
        <input type="hidden" name="plan" value="free">
        <button class="btn-sm btn-free" type="submit">FREE</button>
      </form>
      <form method="post" action="/owner/orgs/{{ r.id }}/toggle_block" style="display:inline;">
        <button class="btn-sm btn-warn" type="submit">{{ '🔓 Разблок.' if r.is_blocked else '🔒 Блок.' }}</button>
      </form>
      <form method="post" action="/owner/orgs/{{ r.id }}/delete" style="display:inline;"
            onsubmit="return confirm('Удалить «{{ r.name }}»? Все данные будут потеряны!');">
        <button class="btn-sm btn-danger" type="submit">🗑 Удалить</button>
      </form>
    </div>
  </div>
  {% endfor %}
  </div>

</div>

<script>
function filterOrgs(q) {
  q = q.toLowerCase().trim();
  document.querySelectorAll('.org-row').forEach(function(row) {
    var text = row.dataset.search || '';
    row.style.display = (!q || text.indexOf(q) !== -1) ? '' : 'none';
  });
}
</script>
</body>
</html>'''


# Создаём таблицы и owner при первом запуске
with app.app_context():
    db.create_all()

    # Автосоздание owner из переменных окружения (для Render/VPS)
    owner_email = os.environ.get('OWNER_EMAIL')
    owner_password = os.environ.get('OWNER_PASSWORD')
    if owner_email and owner_password:
        existing = OwnerUser.query.filter_by(email=owner_email).first()
        if not existing:
            owner = OwnerUser()
            owner.email = owner_email
            owner.set_password(owner_password)
            db.session.add(owner)
            db.session.commit()
            print(f'✅ Owner создан: {owner_email}')

    # Автосоздание демо-компании из переменных окружения
    demo_email = os.environ.get('DEMO_EMAIL')
    demo_password = os.environ.get('DEMO_PASSWORD')
    demo_name = os.environ.get('DEMO_ORG_NAME', 'Демо Бургерная')
    if demo_email and demo_password:
        existing_org = Organization.query.filter_by(owner_email=demo_email).first()
        if not existing_org:
            from datetime import timedelta
            org = Organization(
                name=demo_name,
                owner_email=demo_email,
                email_verified=True,
                plan='trial',
                trial_ends_at=datetime.utcnow() + timedelta(days=30)
            )
            db.session.add(org)
            db.session.flush()
            user = User(org_id=org.id, username='admin', role='admin', email=demo_email)
            user.set_password(demo_password)
            db.session.add(user)
            for loc_name in ['Склад', 'Кухня', 'Островок']:
                db.session.add(Location(org_id=org.id, name=loc_name))
            db.session.commit()
            print(f'✅ Демо-компания создана: {demo_email}')

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host="0.0.0.0", port=port, debug=debug)

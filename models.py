"""
Модели базы данных для Revisi.
Каждый класс = одна таблица в PostgreSQL.
"""
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

db = SQLAlchemy()


# ============== КОМПАНИИ (ТЕНАНТЫ) ==============
class Organization(db.Model):
    """Компания — главная единица мульти-тенантности."""
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    owner_email = db.Column(db.String(255), nullable=False, unique=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verify_token = db.Column(db.String(64), nullable=True)

    # Тариф: 'free', 'trial', 'pro', 'business'
    plan = db.Column(db.String(20), default='trial')
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    subscription_ends_at = db.Column(db.DateTime, nullable=True)

    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Кастомный Excel-шаблон для отчётов (хранится как бинарные данные)
    excel_template = db.Column(db.LargeBinary, nullable=True)

    # Feature-флаги: словарь { 'excel_export': true, 'multi_location': true, ... }
    features = db.Column(db.JSON, nullable=True)

    # Сумма ежемесячной подписки (для MRR), в рублях
    monthly_price = db.Column(db.Integer, default=0)

    # Часовой пояс компании (IANA, напр. 'Europe/Moscow'). Время в БД хранится
    # в UTC, а показывается пользователю в этом поясе.
    timezone = db.Column(db.String(50), default='Europe/Moscow')

    # Связи — все данные компании
    users = db.relationship('User', backref='organization', lazy=True, cascade='all, delete-orphan')
    locations = db.relationship('Location', backref='organization', lazy=True, cascade='all, delete-orphan')
    categories = db.relationship('Category', backref='organization', lazy=True, cascade='all, delete-orphan')
    products = db.relationship('Product', backref='organization', lazy=True, cascade='all, delete-orphan')
    revisions = db.relationship('Revision', backref='organization', lazy=True, cascade='all, delete-orphan')

    def is_trial_active(self):
        return self.plan == 'trial' and self.trial_ends_at and self.trial_ends_at > datetime.utcnow()

    def is_paid(self):
        return self.plan in ('pro', 'business') and self.subscription_ends_at and self.subscription_ends_at > datetime.utcnow()

    def has_premium_access(self):
        return self.is_trial_active() or self.is_paid()


# ============== ПОЛЬЗОВАТЕЛИ КОМПАНИИ ==============
class User(db.Model):
    """Пользователь внутри компании (админ или оператор)."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    username = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default='operator')  # 'admin' или 'operator'

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Логин уникален только в рамках одной компании
    __table_args__ = (
        db.UniqueConstraint('org_id', 'username', name='uq_org_username'),
    )

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


# ============== ЛОКАЦИИ ==============
class Location(db.Model):
    """Склад / Кухня / Островок — у каждой компании свои."""
    __tablename__ = 'locations'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    sort_order = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('org_id', 'name', name='uq_org_location'),
    )


# ============== КАТЕГОРИИ ТОВАРОВ ==============
class Category(db.Model):
    """Напитки / Бургеры / Соусы — у каждой компании свои."""
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    sort_order = db.Column(db.Integer, default=0)

    products = db.relationship('Product', backref='category', lazy=True)

    __table_args__ = (
        db.UniqueConstraint('org_id', 'name', name='uq_org_category'),
    )


# ============== ТОВАРЫ ==============
class Product(db.Model):
    """Товары компании."""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)

    name = db.Column(db.String(300), nullable=False)
    code = db.Column(db.String(100), nullable=True)  # Штрих-код
    unit = db.Column(db.String(20), default='шт')

    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    norms = db.relationship('ProductNorm', backref='product', lazy=True, cascade='all, delete-orphan')


# ============== НОРМЫ ТОВАРОВ ПО ЛОКАЦИЯМ ==============
class ProductNorm(db.Model):
    """Сколько какого товара должно быть на каждой локации."""
    __tablename__ = 'product_norms'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=False)
    norm_qty = db.Column(db.Float, default=0)

    __table_args__ = (
        db.UniqueConstraint('product_id', 'location_id', name='uq_product_location_norm'),
    )


# ============== АССОРТИМЕНТ ЛОКАЦИЙ ==============
class LocationProduct(db.Model):
    """Какие товары входят в ассортимент конкретной локации.
    Если товар не привязан ни к одной локации — он не виден операторам
    и не попадает в ревизии. Это позволяет держать большой каталог товаров
    на компании, но строго регулировать, что считается на каждой точке.
    """
    __tablename__ = 'location_products'

    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('location_id', 'product_id', name='uq_location_product'),
    )


# ============== РЕВИЗИИ (ОТЧЁТЫ) ==============
class Revision(db.Model):
    """Сама ревизия — заголовок отчёта."""
    __tablename__ = 'revisions'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    # user_id и location_id nullable, чтобы при удалении пользователя/локации
    # завершённые ревизии не исчезали из истории — мы просто обнуляем ссылку.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=True)

    # 'in_progress' — идёт, 'pending' — ждёт админа, 'completed' — готова, 'cancelled' — отменена
    status = db.Column(db.String(20), default='in_progress')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    items = db.relationship('RevisionItem', backref='revision', lazy=True, cascade='all, delete-orphan')


class RevisionItem(db.Model):
    """Конкретная запись в ревизии: этот товар посчитали вот столько."""
    __tablename__ = 'revision_items'

    id = db.Column(db.Integer, primary_key=True)
    revision_id = db.Column(db.Integer, db.ForeignKey('revisions.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    # location_id nullable — чтобы при удалении локации позиции уже завершённых
    # ревизий не уничтожались, а просто теряли привязку к удалённой локации.
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=True)

    quantity = db.Column(db.Float, default=0)
    added_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============== SUPER ADMIN (ВЛАДЕЛЕЦ СИСТЕМЫ) ==============
class OwnerUser(db.Model):
    """Вы. Отдельная таблица — не смешиваетесь с пользователями компаний."""
    __tablename__ = 'owner_users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 2FA (TOTP по RFC 6238)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # JSON-список захешированных одноразовых recovery-кодов (на случай потери телефона)
    recovery_codes_json = db.Column(db.Text, nullable=True)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


# ============== АУДИТ ДЕЙСТВИЙ ВЛАДЕЛЬЦА ==============
class OwnerAuditLog(db.Model):
    """Лог всех значимых действий владельца системы."""
    __tablename__ = 'owner_audit_log'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('owner_users.id'), nullable=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    target_org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    target_user_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ============== ТИКЕТЫ ПОДДЕРЖКИ ==============
class SupportTicket(db.Model):
    """Тикет поддержки от клиента владельцу."""
    __tablename__ = 'support_tickets'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    subject = db.Column(db.String(300), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open', index=True)  # open / answered / closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    replies = db.relationship('SupportTicketReply', backref='ticket', lazy=True, cascade='all, delete-orphan')


class SupportTicketReply(db.Model):
    """Ответ в тикете (от клиента или от владельца)."""
    __tablename__ = 'support_ticket_replies'

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support_tickets.id'), nullable=False, index=True)
    author_type = db.Column(db.String(20), nullable=False)  # 'user' or 'owner'
    author_label = db.Column(db.String(150), nullable=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============== ГЛОБАЛЬНЫЙ КАТАЛОГ ТОВАРОВ ==============
class CatalogProduct(db.Model):
    """Дефолтные товары — могут быть импортированы любой компанией одним кликом."""
    __tablename__ = 'catalog_products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300), nullable=False)
    code = db.Column(db.String(100), nullable=True)
    unit = db.Column(db.String(20), default='шт')
    category_name = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============== ЗАЩИТА ОТ БРУТФОРСА ==============
class LoginAttempt(db.Model):
    """Логируем неудачные попытки входа для блокировки брутфорса."""
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    username = db.Column(db.String(100), nullable=True)
    success = db.Column(db.Boolean, default=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

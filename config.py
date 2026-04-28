"""
Конфигурация приложения.
Читает настройки из .env файла или переменных окружения.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Секретный ключ для сессий
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-change-me-in-production')

    # База данных
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://ragimly@localhost:5432/revisi_dev'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Пул соединений: Render Postgres рвёт idle-соединения через ~5 минут,
    # pool_pre_ping проверяет жизнь соединения перед каждым запросом,
    # pool_recycle принудительно пересоздаёт раз в 280 сек.
    # pool_size/max_overflow только для Postgres (SQLite их не принимает).
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
    }
    if SQLALCHEMY_DATABASE_URI.startswith(('postgresql', 'postgres')):
        SQLALCHEMY_ENGINE_OPTIONS['pool_size'] = 5
        SQLALCHEMY_ENGINE_OPTIONS['max_overflow'] = 10

    # Статика кэшируется в браузере на 7 дней (иконки, manifest, sw.js)
    SEND_FILE_MAX_AGE_DEFAULT = 60 * 60 * 24 * 7

    # Сессии — постоянные, 30 дней
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    REMEMBER_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    REMEMBER_COOKIE_HTTPONLY = True

    # CSRF
    WTF_CSRF_ENABLED = True

    # Trial период (дней)
    TRIAL_DAYS = 14

    # Лимиты FREE тарифа
    FREE_MAX_USERS = 3
    FREE_MAX_PRODUCTS = 100
    FREE_MAX_LOCATIONS = 1
    FREE_HISTORY_DAYS = 7

    # Защита от брутфорса
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15

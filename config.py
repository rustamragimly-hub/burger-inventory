"""
Конфигурация приложения.
Читает настройки из .env файла или переменных окружения.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Секретный ключ для сессий
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-change-me-in-production')

    # База данных
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://ragimly@localhost:5432/spurt_dev'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Сессии
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'

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

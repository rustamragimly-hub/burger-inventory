"""Тесты доказательства согласия на обработку ПДн (152-ФЗ).

При регистрации фиксируем факт согласия: момент, IP, User-Agent и версию
юр-документов. Без галочки согласия регистрация не проходит.
"""
import app
import models
from app import LEGAL_DOCS_VERSION

db = app.db


def test_registration_stores_consent_proof(session, app, monkeypatch):
    # Гасим реальную отправку письма: в проде она уходит в фоновый поток,
    # который в тестах гонится с очисткой БД между тестами.
    monkeypatch.setattr('app._send_verify_code_email', lambda *a, **k: True)
    client = app.test_client()
    client.post('/register', data={
        'company': 'ООО Бургер', 'email': 'boss@burger.ru', 'username': 'boss',
        'password': 'secret1', 'password2': 'secret1',
        'pos_system': 'excel', 'terms': 'on',
    }, headers={
        'User-Agent': 'TestBrowser/1.0',
        'X-Forwarded-For': '203.0.113.7, 10.0.0.1',
    })

    org = models.Organization.query.filter_by(owner_email='boss@burger.ru').first()
    assert org is not None
    assert org.consent_at is not None
    # Берём первый IP из X-Forwarded-For (реальный клиент, не прокси)
    assert org.consent_ip == '203.0.113.7'
    assert org.consent_user_agent == 'TestBrowser/1.0'
    assert org.consent_version == LEGAL_DOCS_VERSION


def test_registration_rejected_without_consent(session, app):
    client = app.test_client()
    client.post('/register', data={
        'company': 'ООО Без Галочки', 'email': 'no@consent.ru', 'username': 'u',
        'password': 'secret1', 'password2': 'secret1', 'pos_system': 'excel',
        # terms не передаём — согласие не дано
    })
    # Компания не должна быть создана
    assert models.Organization.query.filter_by(owner_email='no@consent.ru').first() is None

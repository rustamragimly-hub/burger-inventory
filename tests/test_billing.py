"""Тесты биллинга: автоблокировка по просрочке и письма-напоминания.

Критичное место — деньги и доступ клиента, поэтому фиксируем регрессионными
тестами: истёкшая подписка перекрывает доступ (кроме /billing), а cron шлёт
ровно по одному письму в день в окне «за 3 дня до конца».
"""
from datetime import datetime, timedelta, date
import app
import models

db = app.db

_ORG_SEQ = [0]


def _paid_org(org_factory, days_from_now, plan='pro'):
    """Компания на платном тарифе с подпиской, истекающей через N дней
    (N<0 — уже истекла). Имя уникальное, чтобы не ловить коллизию owner_email."""
    _ORG_SEQ[0] += 1
    org, locs, prods = org_factory(name=f'Орг{_ORG_SEQ[0]}', products=[], locations=('Точка',))
    org.plan = plan
    org.subscription_ends_at = datetime.utcnow() + timedelta(days=days_from_now)
    org.renewal_reminder_last_sent = None
    db.session.commit()
    return org


# ─────────────────────── Модель ───────────────────────

def test_subscription_expired_flag(session, org_factory):
    active = _paid_org(org_factory, days_from_now=5)
    expired = _paid_org(org_factory, days_from_now=-1)
    assert active.subscription_expired() is False
    assert expired.subscription_expired() is True


def test_free_and_trial_never_expire_via_subscription(session, org_factory):
    org = _paid_org(org_factory, days_from_now=-10, plan='free')
    assert org.subscription_expired() is False
    org.plan = 'trial'
    org.trial_ends_at = datetime.utcnow() - timedelta(days=1)
    db.session.commit()
    # trial-просрочка не считается subscription_expired (это отдельный флаг)
    assert org.subscription_expired() is False


# ─────────────────────── Access-guard ───────────────────────

def _make_user(org, role='admin'):
    u = models.User(org_id=org.id, username='u1', email='u1@t.ru', role=role)
    u.set_password('secret1')
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = f'u:{user.id}'
        sess['_fresh'] = True


def test_expired_org_redirected_to_billing(session, org_factory):
    org = _paid_org(org_factory, days_from_now=-1)
    user = _make_user(org)
    client = app.app.test_client()
    _login(client, user)
    resp = client.get('/admin', follow_redirects=False)
    assert resp.status_code == 302
    assert '/billing' in resp.headers.get('Location', '')


def test_expired_org_can_reach_billing(session, org_factory):
    org = _paid_org(org_factory, days_from_now=-1)
    user = _make_user(org)
    client = app.app.test_client()
    _login(client, user)
    resp = client.get('/billing', follow_redirects=False)
    assert resp.status_code == 200
    assert 'Подписка истекла' in resp.get_data(as_text=True)


def test_active_org_not_redirected(session, org_factory):
    org = _paid_org(org_factory, days_from_now=10)
    user = _make_user(org)
    client = app.app.test_client()
    _login(client, user)
    resp = client.get('/admin', follow_redirects=False)
    # активная подписка → на /billing не выкидывает (может быть 200 или иной
    # редирект, но точно не на /billing)
    assert '/billing' not in resp.headers.get('Location', '')


# ─────────────────────── Cron-напоминания ───────────────────────

def _run_cron(monkeypatch):
    sent = []
    monkeypatch.setattr(app, '_send_email',
                        lambda to, subj, html, text=None: sent.append((to, subj)) or True)
    runner = app.app.test_cli_runner()
    result = runner.invoke(args=['billing-cron'])
    return sent, result


def test_reminder_sent_within_3_days(session, org_factory, monkeypatch):
    org = _paid_org(org_factory, days_from_now=3)
    sent, result = _run_cron(monkeypatch)
    assert len(sent) == 1
    assert sent[0][0] == org.owner_email
    db.session.refresh(org)
    assert org.renewal_reminder_last_sent == date.today()


def test_no_reminder_beyond_window(session, org_factory, monkeypatch):
    _paid_org(org_factory, days_from_now=5)   # слишком рано
    _paid_org(org_factory, days_from_now=-1)  # уже истекла (не напоминаем)
    sent, _ = _run_cron(monkeypatch)
    assert sent == []


def test_reminder_idempotent_same_day(session, org_factory, monkeypatch):
    org = _paid_org(org_factory, days_from_now=2)
    sent1, _ = _run_cron(monkeypatch)
    sent2, _ = _run_cron(monkeypatch)  # второй прогон в тот же день
    assert len(sent1) == 1
    assert sent2 == []  # повторно не шлём


def test_free_plan_gets_no_reminder(session, org_factory, monkeypatch):
    _paid_org(org_factory, days_from_now=2, plan='free')
    sent, _ = _run_cron(monkeypatch)
    assert sent == []

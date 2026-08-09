"""Общие фикстуры для тестов Revisi.

Импортируем приложение с тестовой SQLite-БД (вместо боевого Postgres) —
переменные окружения выставляются ДО импорта app, чтобы config.py их подхватил.
"""
import os
import tempfile

# Тестовое окружение — задаём до импорта app/config.
_TMP_DB = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_TMP_DB.close()
os.environ['DATABASE_URL'] = f'sqlite:///{_TMP_DB.name}'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ.setdefault('FLASK_ENV', 'testing')

import pytest  # noqa: E402
from app import app as flask_app, db  # noqa: E402
import models  # noqa: E402


@pytest.fixture(scope='session')
def app():
    flask_app.config['TESTING'] = True
    with flask_app.app_context():
        db.create_all()
        yield flask_app


@pytest.fixture()
def session(app):
    """Чистая БД и чистая сессия на каждый тест.

    Пересоздаём схему и сбрасываем scoped-сессию: постоянная сессия внешнего
    app-контекста иначе копит объекты в identity map, а SQLite переиспользует
    id после DELETE — «протухший» объект прошлого теста сталкивается с новым и
    ломает flush. remove() + drop/create дают полностью чистый старт."""
    yield db.session
    db.session.remove()
    db.drop_all()
    db.create_all()


@pytest.fixture()
def org_factory(session):
    """Фабрика: создаёт компанию с локациями и товарами."""
    def _make(name='ООО Тест', products=None, locations=('Склад', 'Кухня')):
        org = models.Organization(name=name, owner_email=f'{name}@test.ru'.replace(' ', ''),
                                   email_verified=True, plan='pro')
        db.session.add(org)
        db.session.flush()
        locs = []
        for i, ln in enumerate(locations):
            loc = models.Location(org_id=org.id, name=ln, sort_order=i)
            db.session.add(loc)
            locs.append(loc)
        db.session.flush()
        prods = []
        for code, pname, unit in (products or []):
            p = models.Product(org_id=org.id, name=pname, code=code, unit=unit)
            db.session.add(p)
            prods.append(p)
        db.session.flush()
        return org, locs, prods
    return _make

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
    """Чистая БД на каждый тест: откатываем все данные после теста."""
    yield db.session
    db.session.rollback()
    # Чистим таблицы между тестами, чтобы они не влияли друг на друга.
    for table in reversed(db.metadata.sorted_tables):
        db.session.execute(table.delete())
    db.session.commit()


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

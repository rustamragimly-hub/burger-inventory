"""Тесты замены списка товаров по новому бланку (_replace_products_from_blank).

Правило: товары из нового бланка обновляются/создаются; те, кого в бланке нет,
архивируются (если есть история ревизий) или удаляются (если истории нет).
История прошлых ревизий не разрушается.
"""
from datetime import datetime
import app
import models

db = app.db


def _lp(loc, prod):
    db.session.add(models.LocationProduct(location_id=loc.id, product_id=prod.id))


def test_replace_updates_creates_archives_and_deletes(session, org_factory):
    org, locs, prods = org_factory(
        products=[('100', 'Кола', 'шт'), ('101', 'Фанта', 'шт'), ('102', 'Спрайт', 'шт')],
        locations=('Склад',),
    )
    loc = locs[0]
    kola, fanta, sprite = prods
    for p in prods:
        _lp(loc, p)
    # У Фанты (101) есть история ревизии → её нельзя удалять, только архивировать
    rev = models.Revision(org_id=org.id, location_id=loc.id, status='completed',
                          finished_at=datetime(2026, 8, 1, 10, 0))
    db.session.add(rev); db.session.flush()
    db.session.add(models.RevisionItem(revision_id=rev.id, product_id=fanta.id,
                                       location_id=loc.id, quantity=5))
    db.session.commit()

    # Новый бланк: Кола (обновлённое имя), новый товар Вода. Фанты и Спрайта нет.
    rows = [
        {'Категория': 'Напитки', 'Название': 'Кола 0,5', 'Код': '100', 'Ед. изм.': 'шт'},
        {'Категория': 'Напитки', 'Название': 'Вода', 'Код': '200', 'Ед. изм.': 'шт'},
    ]
    stats = app._replace_products_from_blank(org.id, rows)
    db.session.commit()

    assert stats == {'created': 1, 'updated': 1, 'retired': 1, 'deleted': 1}

    # Кола обновлена и активна
    k = models.Product.query.filter_by(org_id=org.id, code='100').first()
    assert k.name == 'Кола 0,5' and k.is_active is True
    # Фанта архивирована (история!) — не удалена, но неактивна
    fa = models.Product.query.filter_by(org_id=org.id, code='101').first()
    assert fa is not None and fa.is_active is False
    # Спрайт удалён (истории не было)
    assert models.Product.query.filter_by(org_id=org.id, code='102').first() is None
    # Вода создана и активна
    w = models.Product.query.filter_by(org_id=org.id, code='200').first()
    assert w is not None and w.is_active is True

    # История Фанты цела
    assert models.RevisionItem.query.filter_by(product_id=fanta.id).count() == 1

    # Ассортимент: Вода добавлена в локацию, Фанта убрана
    lp_pids = {lp.product_id for lp in models.LocationProduct.query.filter_by(location_id=loc.id).all()}
    assert w.id in lp_pids
    assert fanta.id not in lp_pids


def test_replace_matches_by_code_keeps_history_product_active(session, org_factory):
    """Товар с историей, присутствующий в новом бланке, остаётся активным
    и обновляется (а не архивируется)."""
    org, locs, prods = org_factory(
        products=[('100', 'Кола', 'шт')], locations=('Склад',),
    )
    loc = locs[0]
    kola = prods[0]
    _lp(loc, kola)
    rev = models.Revision(org_id=org.id, location_id=loc.id, status='completed',
                          finished_at=datetime(2026, 8, 1))
    db.session.add(rev); db.session.flush()
    db.session.add(models.RevisionItem(revision_id=rev.id, product_id=kola.id,
                                       location_id=loc.id, quantity=3))
    db.session.commit()

    rows = [{'Категория': '', 'Название': 'Кола обновлённая', 'Код': '100', 'Ед. изм.': 'л'}]
    stats = app._replace_products_from_blank(org.id, rows)
    db.session.commit()

    assert stats['updated'] == 1 and stats['retired'] == 0 and stats['deleted'] == 0
    k = models.Product.query.filter_by(org_id=org.id, code='100').first()
    assert k.is_active is True and k.name == 'Кола обновлённая' and k.unit == 'л'

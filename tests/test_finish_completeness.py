"""Тесты проверки полноты при завершении ревизии.

Правило: оператор не может отправить ревизию на завершение, пока по каждому
товару ассортимента завершаемой локации не внесены показания (в т.ч. явный 0
через /revision/mark_zero). Прежней автопростановки «0» непосчитанным позициям
больше нет — их нужно внести вручную.
"""
import app
import models

db = app.db


def _login(client, org, role='operator'):
    """Создаёт пользователя и логинит его в сессии клиента."""
    user = models.User(org_id=org.id, username=f'op_{role}', role=role)
    user.set_password('pass12345')
    db.session.add(user)
    db.session.commit()
    with client.session_transaction() as sess:
        # Flask-Login хранит id пользователя в ключе '_user_id';
        # формат id — '<prefix>:<raw_id>' (см. load_user).
        sess['_user_id'] = f'u:{user.id}'
    return user


def _assortment(loc, prods):
    for p in prods:
        db.session.add(models.LocationProduct(location_id=loc.id, product_id=p.id))
    db.session.commit()


def test_finish_blocked_until_all_counted(session, org_factory, app):
    org, locs, prods = org_factory(
        products=[('1', 'Кола', 'шт'), ('2', 'Фанта', 'шт'), ('3', 'Спрайт', 'шт')],
        locations=('Склад',),
    )
    sklad = locs[0]
    _assortment(sklad, prods)
    client = app.test_client()
    _login(client, org)

    # Считаем только один товар из трёх
    r = client.post('/revision/add', data={
        'location_id': sklad.id, 'product_id': prods[0].id, 'count': '5',
    })
    assert r.get_json()['ok'] is True

    # Завершение должно быть заблокировано с перечнем пропущенных
    r = client.post('/revision/finish', data={'location_id': sklad.id})
    data = r.get_json()
    assert r.status_code == 400
    assert data['ok'] is False
    assert data['missing_total'] == 2
    names = {n for block in data['missing'] for n in block['products']}
    assert names == {'Фанта', 'Спрайт'}


def test_mark_zero_counts_as_filled(session, org_factory, app):
    org, locs, prods = org_factory(
        products=[('1', 'Кола', 'шт'), ('2', 'Фанта', 'шт')],
        locations=('Склад',),
    )
    sklad = locs[0]
    _assortment(sklad, prods)
    client = app.test_client()
    _login(client, org)

    client.post('/revision/add', data={
        'location_id': sklad.id, 'product_id': prods[0].id, 'count': '5',
    })
    # Второй товар — «нет в наличии», явный 0
    r = client.post('/revision/mark_zero', data={
        'location_id': sklad.id, 'product_id': prods[1].id,
    })
    assert r.get_json()['ok'] is True

    # Теперь все позиции внесены — завершение проходит
    r = client.post('/revision/finish', data={'location_id': sklad.id})
    data = r.get_json()
    assert r.status_code == 200, data
    assert data['ok'] is True
    assert data['locations_finished'] == 1

    rev = models.Revision.query.filter_by(org_id=org.id).first()
    assert rev.status == 'pending'


def test_mark_zero_is_idempotent_and_keeps_existing_count(session, org_factory, app):
    org, locs, prods = org_factory(
        products=[('1', 'Кола', 'шт')], locations=('Склад',),
    )
    sklad = locs[0]
    _assortment(sklad, prods)
    client = app.test_client()
    _login(client, org)

    # Сначала реальное показание, затем mark_zero не должен затирать сумму
    client.post('/revision/add', data={
        'location_id': sklad.id, 'product_id': prods[0].id, 'count': '7',
    })
    r = client.post('/revision/mark_zero', data={
        'location_id': sklad.id, 'product_id': prods[0].id,
    })
    assert r.get_json()['total'] == 7.0


def test_finish_blocked_when_another_location_incomplete(session, org_factory, app):
    org, locs, prods = org_factory(
        products=[('1', 'Кола', 'шт'), ('2', 'Фанта', 'шт')],
        locations=('Склад', 'Кухня'),
    )
    sklad, kuhnya = locs
    _assortment(sklad, prods)
    _assortment(kuhnya, prods)
    client = app.test_client()
    _login(client, org)

    # Склад посчитан полностью
    for p in prods:
        client.post('/revision/add', data={
            'location_id': sklad.id, 'product_id': p.id, 'count': '3',
        })
    # Кухня — только один товар
    client.post('/revision/add', data={
        'location_id': kuhnya.id, 'product_id': prods[0].id, 'count': '2',
    })

    r = client.post('/revision/finish', data={'location_id': sklad.id})
    data = r.get_json()
    assert r.status_code == 400
    assert data['missing_total'] == 1
    assert data['missing'][0]['location'] == 'Кухня'
    assert data['missing'][0]['products'] == ['Фанта']

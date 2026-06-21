"""Тесты чистки названий товаров от сокращения «в асс» (двусмысленное)."""
import app


def test_strips_v_ass_variants():
    assert app._sanitize_product_name('Батончик Бомбар в асс (40,45,60г)') == 'Батончик Бомбар (40,45,60г)'
    assert app._sanitize_product_name('Шоколад в асс.') == 'Шоколад'
    assert app._sanitize_product_name('Шоколад (в асс)') == 'Шоколад'
    assert app._sanitize_product_name('Конфеты в ассорт.') == 'Конфеты'
    assert app._sanitize_product_name('Печенье в ассортименте') == 'Печенье'


def test_keeps_legitimate_words():
    # «ассорти» и «ассистент» не должны пострадать
    assert app._sanitize_product_name('Карамель в ассорти') == 'Карамель в ассорти'
    assert app._sanitize_product_name('Помощник в ассистенте') == 'Помощник в ассистенте'


def test_untouched_plain_names():
    assert app._sanitize_product_name('Кола 0,5 л') == 'Кола 0,5 л'
    assert app._sanitize_product_name('Аромат. напиток Мартини Розато 0,25') == 'Аромат. напиток Мартини Розато 0,25'


def test_empty_and_none():
    assert app._sanitize_product_name('') == ''
    assert app._sanitize_product_name(None) is None

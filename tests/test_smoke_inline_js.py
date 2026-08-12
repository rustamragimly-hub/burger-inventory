"""Pytest-обёртка над smoke-тестом inline-JS (см. smoke_inline_js.py).

Гоняет весь inline-JavaScript всех HTML-шаблонов через `node --check`, чтобы
поймать синтаксически сломанный скрипт до того, как он уедет в браузер —
класс багов, который обычный pytest не видит (пример: коммит 921b3c1,
литеральный перенос строки в confirmReplaceBlank ломал ВЕСЬ скрипт админки).

Пропускается, если в окружении нет node.
"""
import pytest

from smoke_inline_js import check_all, node_available


@pytest.mark.skipif(not node_available(), reason='node не установлен')
def test_inline_js_is_valid_syntax():
    results = check_all()
    assert results, 'не найдено ни одного *_html шаблона со <script>'
    broken = [(name, detail) for name, status, detail in results
              if status == 'fail']
    assert not broken, 'Сломанный inline-JS в шаблонах:\n' + '\n'.join(
        f'  {name}: {detail.splitlines()[0] if detail else "?"}'
        for name, detail in broken)

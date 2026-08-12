#!/usr/bin/env python3
"""Smoke-тест inline-JS во всех HTML-шаблонах app.py.

Ловит класс багов, который pytest не видит: синтаксически сломанный
JavaScript, уходящий в браузер (например, литеральный перенос строки внутри
одинарных кавычек — баг confirmReplaceBlank, из-за которого падал ВЕСЬ
inline-скрипт админки, коммит 921b3c1).

Как работает:
  1. Импортирует app и берёт РАНТАЙМ-значения всех строковых шаблонов `*_html`.
     Важно: именно рантайм-значение, а не текст файла — баг с переносом строки
     существует только в вычисленной Python-строке ('''...\\n...''' → реальный
     перенос), а в байтах файла лежит безобидное `\\n`.
  2. Рендерит каждый через НАСТОЯЩИЙ Jinja движка приложения — с «мягким»
     Undefined: условия берут ложную ветку, циклы пусты, {{ x }} → 0. Так
     остаётся ровно одна ветка ({% if %}/{% else %}), а не обе склеенные,
     и статический текст (где и прячется баг с переносом строки) сохраняется
     дословно.
  3. Вырезает содержимое каждого <script>…</script>.
  4. Прогоняет JS каждого шаблона через `node --check`.

Возвращает ненулевой код при первой синтаксической ошибке. Требует node.
"""
import os
import re
import subprocess
import sys
import tempfile

# Тестовое окружение — как в conftest, чтобы app импортировался с SQLite.
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('SECRET_KEY', 'smoke-secret')
os.environ.setdefault('FLASK_ENV', 'testing')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

SCRIPT_RE = re.compile(r'<script\b[^>]*>(.*?)</script>', re.S | re.I)


def node_available():
    try:
        subprocess.run(['node', '--version'], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def make_env():
    """Jinja-окружение приложения + мягкий Undefined для рендера без контекста."""
    import jinja2
    from app import app as flask_app

    class SmokeUndef(jinja2.ChainableUndefined):
        # {{ x }} -> 0 (валидный JS-токен вместо пустоты, дающей "var a = ;")
        def __str__(self):
            return '0'
        __html__ = __str__

        def __iter__(self):
            return iter(())  # {% for %} по неизвестному -> пусто

        def __call__(self, *a, **k):
            return self      # {{ icon('...') }} и прочие хелперы из контекста

    env = flask_app.jinja_env.overlay(undefined=SmokeUndef)
    return flask_app, env


def collect_templates():
    """Рантайм-значения всех строковых шаблонов *_html из модуля app."""
    import app as app_module
    out = []
    for name in sorted(vars(app_module)):
        if name.endswith('_html'):
            val = getattr(app_module, name)
            if isinstance(val, str):
                out.append((name, val))
    return out


def _node_check(js):
    """Возвращает (ok, stderr) для куска JS через `node --check`."""
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False,
                                     encoding='utf-8') as fh:
        fh.write(js)
        path = fh.name
    try:
        r = subprocess.run(['node', '--check', path],
                           capture_output=True, text=True)
    finally:
        os.unlink(path)
    return r.returncode == 0, r.stderr


def check_all():
    """Проверяет inline-JS всех шаблонов. Возвращает список результатов:
    (name, status, detail), где status ∈ {'ok', 'fail', 'render-warn'}."""
    flask_app, env = make_env()
    results = []
    with flask_app.app_context(), flask_app.test_request_context('/'):
        for name, body in collect_templates():
            if '<script' not in body.lower():
                continue
            try:
                html = env.from_string(body).render()
            except Exception as e:  # noqa: BLE001
                results.append((name, 'render-warn', f'{type(e).__name__}: {e}'))
                continue
            scripts = SCRIPT_RE.findall(html)
            if not scripts:
                continue
            ok, stderr = _node_check('\n;\n'.join(scripts))
            results.append((name, 'ok' if ok else 'fail', stderr.strip()))
    return results


def main():
    if not node_available():
        print('SKIP: node не найден — smoke-тест inline-JS пропущен')
        return 0
    results = check_all()
    if not results:
        sys.exit('ОШИБКА: не найдено ни одного *_html шаблона со <script>')

    failed = 0
    for name, status, detail in results:
        if status == 'ok':
            print(f'  OK   {name}')
        elif status == 'render-warn':
            print(f'  WARN {name}: не отрендерился ({detail})')
        else:
            failed += 1
            print(f'  FAIL {name}')
            for line in detail.splitlines()[:4]:
                if line.strip():
                    print('       ' + line.strip())

    checked = sum(1 for _, s, _ in results if s in ('ok', 'fail'))
    warns = sum(1 for _, s, _ in results if s == 'render-warn')
    print(f'\nПроверено шаблонов со скриптами: {checked}, '
          f'синтакс-ошибок: {failed}, не отрендерилось: {warns}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

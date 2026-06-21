"""Тесты конвертации времени в часовой пояс компании."""
from datetime import datetime
import app


class _Org:
    def __init__(self, tz):
        self.timezone = tz


def test_utc_to_moscow():
    # 18:51 UTC -> 21:51 МСК (+3)
    dt = datetime(2026, 6, 9, 18, 51)
    assert app._fmt_dt(dt, _Org('Europe/Moscow'), fmt='%H:%M') == '21:51'


def test_default_is_moscow_when_no_org():
    dt = datetime(2026, 6, 9, 18, 51)
    assert app._fmt_dt(dt, None, fmt='%H:%M') == '21:51'


def test_other_timezone():
    # Екатеринбург +5 -> 23:51
    dt = datetime(2026, 6, 9, 18, 51)
    assert app._fmt_dt(dt, _Org('Asia/Yekaterinburg'), fmt='%H:%M') == '23:51'


def test_invalid_timezone_falls_back_to_moscow():
    dt = datetime(2026, 6, 9, 18, 51)
    assert app._fmt_dt(dt, _Org('Mars/Olympus'), fmt='%H:%M') == '21:51'


def test_none_datetime():
    assert app._fmt_dt(None, _Org('Europe/Moscow')) == ''

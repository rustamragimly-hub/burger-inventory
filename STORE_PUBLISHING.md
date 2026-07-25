# Публикация Revisi в сторах

Revisi — веб-приложение (`app.revisi.ru`). В сторы попадает через обёртку поверх
готового PWA. Ниже — рабочий план. App Store отложен (нужен Mac + Apple-аккаунт).

## Что уже сделано в коде (PWA-фундамент)

- `manifest.json` — по требованиям Play/PWABuilder (standalone, maskable-иконка,
  id, lang, categories).
- Service worker регистрируется с корневым scope (`/sw.js`), даёт офлайн-оболочку
  (`static/offline.html`) и push-уведомления.
- `GET /.well-known/assetlinks.json` — отдаётся приложением (для верификации TWA).

Проверить готовность: открыть https://app.revisi.ru в Chrome на телефоне →
меню → «Установить приложение». Должно ставиться как отдельное приложение.

---

## Google Play (через TWA / PWABuilder) — приоритетный путь

Стоимость: **$25 разово** (Google Play Developer). Mac НЕ нужен.

1. **Аккаунт разработчика.** Зарегистрировать Google Play Developer:
   https://play.google.com/console — оплатить $25, заполнить данные.

2. **Сгенерировать пакет.** Открыть https://www.pwabuilder.com → вставить
   `https://app.revisi.ru` → «Package for stores» → Android.
   - Package ID указать: **`ru.revisi.app`** (должен совпадать с `assetlinks.json`).
   - Скачать zip: внутри `.aab` (для загрузки) + `signing-key-info` с отпечатком.

3. **Прописать отпечаток подписи.** Из PWABuilder взять `SHA-256 fingerprint`
   и вставить в [`static/.well-known/assetlinks.json`](static/.well-known/assetlinks.json)
   вместо `REPLACE_WITH_SHA256_FINGERPRINT_FROM_PWABUILDER`. Закоммитить, задеплоить.
   Проверить: `curl https://app.revisi.ru/.well-known/assetlinks.json` — отпечаток
   виден. Без этого в приложении останется адресная строка браузера.

4. **Загрузить в Play Console.** Создать приложение → загрузить `.aab` →
   заполнить карточку (описание, иконка, **минимум 2 скриншота телефона**,
   политика конфиденциальности → https://revisi.ru/privacy) → отправить на ревью.
   Проверка обычно 1–3 дня.

Примечание: keystore из PWABuilder **сохранить** (без него не выпустить обновления).
Проще включить Google Play App Signing — тогда ключом управляет Google.

---

## App Store (отложено)

Нужны: **Mac + Xcode**, **Apple Developer ($99/год)**, рабочий способ оплаты (из РФ
проблемно с 2022). Плюс два важных нюанса:

- **Apple IAP.** Продажу подписки Apple требует через свой In-App Purchase (−30%).
  Решение: в iOS-приложении подписку НЕ показывать — оформление на сайте, в приложении
  только вход. Позиционировать как рабочий инструмент.
- **Guideline 4.2.** «Голую» обёртку сайта отклоняют. Добавить нативную ценность —
  например **сканер штрихкодов камерой** (через Capacitor). Заодно ускоряет ревизии.

Когда появятся Mac + аккаунт: оборачиваем в Capacitor (iOS + Android из одного кода),
добавляем сканер, собираем в Xcode, грузим через App Store Connect.

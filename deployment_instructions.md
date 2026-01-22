# 🚀 Инструкция по деплою на Render

Этот документ описывает шаги для запуска вашего приложения `burger-inventory` на платформе **Render**.

## 1. Подготовка (уже сделано)
Мы проверили конфигурацию файлов:
- `requirements.txt`: Список библиотек (Flask, gunicorn, openpyxl).
- `render.yaml`: Конфигурация сервиса для Render.
- `Procfile`: Команда для запуска.

> **⚠️ ВАЖНО:** Приложение хранит данные (остатки, историю) **в оперативной памяти**. При перезапуске сервера на Render все данные будут **сброшены**.

## 2. Загрузка кода на GitHub
Чтобы Render мог скачать ваше приложение, код должен быть на GitHub (или GitLab/Bitbucket).

1.  Создайте новый репозиторий на GitHub.
2.  Выполните команды в терминале папки с проектом:
    ```bash
    git init
    git add .
    git commit -m "Initial commit for Render"
    git branch -M main
    git remote add origin https://github.com/ВАШ_НИК/ВАШ_РЕПОЗИТОРИЙ.git
    git push -u origin main
    ```

## 3. Настройка на Render
1.  Зарегистрируйтесь или войдите на [dashboard.render.com](https://dashboard.render.com/).
2.  Нажмите кнопку **New +** и выберите **Web Service**.
3.  Выберите **Build and deploy from a Git repository**.
4.  Подключите свой GitHub аккаунт и выберите репозиторий, который вы создали.
5.  Render автоматически определит настройки из `render.yaml`, если он есть. Если нет, заполните вручную:
    -   **Name**: `burger-inventory` (или любое другое)
    -   **Region**: `Frankfurt` (ближе к РФ) или `Oregon`
    -   **Branch**: `main`
    -   **Runtime**: `Python 3`
    -   **Build Command**: `pip install -r requirements.txt`
    -   **Start Command**: `gunicorn app:app`
    -   **Plan**: `Free`

6.  Нажмите **Create Web Service**.

## 4. Проверка работы
1.  Ждите, пока деплой завершится (статус **Live** зелёным цветом).
2.  Перейдите по ссылке, которую выдаст Render (например, `https://burger-inventory.onrender.com`).
3.  Войдите под логином администратора:
    -   **Логин**: `admin`
    -   **Пароль**: `admin123`

## 5. Обновление
Если вы внесли изменения в код:
1.  `git add .`
2.  `git commit -m "Update code"`
3.  `git push`
Render автоматически увидит изменения и пересобирет приложение.

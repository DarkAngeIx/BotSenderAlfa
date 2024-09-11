# BotSenderAlfa

### Описание проекта
Этот проект реализует Telegram-бота для получения и отправки информации о банковских транзакциях с использованием API Альфа банка. Бот выполняет аутентификацию, получает токены доступа и обновляет их, а затем периодически запрашивает транзакции со счета и отправляет их в заданный Telegram-чат.

### Установка

1. Клонируйте репозиторий:
    ```sh
    git clone git@github.com:DarkAngeIx/BotSenderAlfa.git
    ```

2. Перейдите в директорию проекта:
    ```sh
    cd BotSenderAlfa

    ```

3. Установите необходимые зависимости:
    ```sh
    pip install -r requirements.txt
    ```

### Конфигурация

1. Создайте и заполните файл `config.py` следующими данными:

```python
BOT_TOKEN = ''  # Токен телеграмм бота
CLIENT_ID = ''  # Логин (получается от банка)
CLIENT_SECRET = ""  # Пароль (получается запросом)

CERT_FILE = ''  # путь к фалйу .cert (Сертификат)
KEY_FILE = ''  # путь к файлу .key (Ключ)
REDIRECT_URI = ''  # Переадресация для auth_url (стандартный http://localhost)

ALLOWED_USERS = []  # Список разрешённых пользователей к команде /auth
CHAT_ID = ''  # ID чата телеграмм, в который будут отправлены сообщения
ACCOUNT_NUMBER = ''  # Номер счета банка 

URL_TOKEN_GET = "https://baas.alfabank.ru/oidc/token"
URL_GET_TRANSACTIONS = 'https://baas.alfabank.ru/api/statement/transactions'
TOKEN_URL = 'https://id.alfabank.ru/oidc/authorize'
```

### Запуск

1. Запустите файл бота `bot_sender.py`:
    ```sh
    python bot_sender.py
    ```

### Использование

- Команда `/auth <auth_code>`: запуск аутентификации бота с использованием кода авторизации.
- Получение новых транзакций осуществляется автоматически каждые три минуты и если есть новые отправляется в заданный чат.

### Пример вывода сообщения в телеграмм

```
Отправитель        | Общество с ограниченой ответственностью "Ромашка"
Дата               | 10.01.2020 07:28
Сумма              | 15500.0 РУБ
Назначение платежа | Оплата (предоплата) за строительные материалы по счету
                     № 111 от 01.08.2023.
```
    

### Основные компоненты

- **TokenManager**: Класс для управления токенами доступа и обновления.
- **process_transactions**: Функция для обработки полученных транзакций и форматирования их для отправки.
- **send_transactions**: Функция для отправки транзакций в чат.
- **periodic_statement_request**: Функция для периодического запроса транзакций и обновления токена.

### Важные моменты

- Все настройки бота и параметры API находятся в файле `config.py`.
- Убедитесь, что все необходимые разрешения и сертификаты установлены правильно. Какие именно данные нужны для конфигурации в файле `config.
- Более подробно о интеграции AlfaAPI описано в [документации](https://developers.alfabank.ru/products/alfa-api/documentation/articles/specification/articles/intro/intro).

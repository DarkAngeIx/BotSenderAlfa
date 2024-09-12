import telebot
import threading
import time
import warnings
import requests
from flask import Flask, request
from datetime import datetime
import textwrap
from config import *

warnings.filterwarnings("ignore")

app = Flask(__name__)
bot = telebot.TeleBot(BOT_TOKEN)

processed_transaction_ids = set()


class TokenManager:
    def __init__(self, client_id, client_secret, redirect_uri, cert_file, key_file):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.cert_file = cert_file
        self.key_file = key_file
        self.access_token = None
        self.refresh_token = None
        self.token_expiry_time = None

    def get_tokens(self, auth_code):
        url = URL_TOKEN_GET
        payload = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'code_verifier': 'string'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        response = requests.post(url, cert=(self.cert_file, self.key_file), headers=headers, data=payload, verify=False)

        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry_time = time.time() + data['expires_in']
        else:
            raise Exception(f"Failed to get tokens: {response.status_code}")

    def refresh_token_method(self):
        url = URL_TOKEN_GET
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        response = requests.post(url, cert=(self.cert_file, self.key_file), headers=headers, data=payload, verify=False)

        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry_time = time.time() + data['expires_in']
            print(f"Токен успешно обновлён.")
        else:
            raise Exception(f"Ошибка при обновлении токена: {response.status_code}")

    def get_access_token(self):
        if self.access_token is None or time.time() >= self.token_expiry_time:
            if self.refresh_token is None:
                raise Exception("Токен недоступен, срок действия токена обновления истек.")
            self.refresh_token_method()
        return self.access_token


def get_transactions(access_token):
    today_date = datetime.now().strftime("%Y-%m-%d")
    account_number = ACCOUNT_NUMBER
    url_get_transactions = URL_GET_TRANSACTIONS
    url = f"{url_get_transactions}?accountNumber={account_number}&statementDate={today_date}&page=1&curFormat=curTransfer"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }

    for attempt in range(3):
        try:
            response = requests.get(url, cert=(CERT_FILE, KEY_FILE), headers=headers, verify=False, timeout=10)
            if response.status_code == 200:
                transactions = response.json().get('transactions', [])
                return [t for t in transactions if t.get('direction') == 'CREDIT']
            else:
                print(f"Ошибка получения транзакций: {response.status_code}")
        except (requests.exceptions.RequestException, TimeoutError) as e:
            print(f"Попытка {attempt + 1} не удалась: {str(e)}")
            time.sleep(5)
    return []


def process_transactions(transactions):
    global processed_transaction_ids

    def format_transaction(transaction):
        sender = transaction.get('rurTransfer', {}).get('payerName', "Не указано")
        date_iso = transaction.get('operationDate', "Не указано")
        date = convert_date(date_iso) if date_iso != "Не указано" else date_iso
        amount_info = transaction.get('amount', {})
        amount = amount_info.get('amount', "Не указано")
        currency = "РУБ" if amount_info.get('currencyName') == "RUR" else amount_info.get('currencyName', "Не указано")
        payment_purpose = transaction.get('paymentPurpose', "Не указано")
        transaction_id = transaction.get('transactionId', "Не указано")

        formatted_transaction = (
            f"Отправитель        | {sender}\n"
            f"Дата               | {date}\n"
            f"Сумма              | {amount} {currency}\n"
            f"Назначение платежа | {wrap_text(payment_purpose, 65, 21)}\n"
        )
        return transaction_id, formatted_transaction

    new_transactions = [format_transaction(transaction) for transaction in transactions if
                        transaction.get('transactionId') not in processed_transaction_ids]

    if new_transactions:
        for transaction_id, _ in new_transactions:
            processed_transaction_ids.add(transaction_id)

    return [formatted_transaction for _, formatted_transaction in new_transactions]


def wrap_text(text, max_width, indent):
    wrapped_lines = textwrap.wrap(text, width=max_width)
    indented_lines = [wrapped_lines[0]] + [(" " * indent + line) for line in wrapped_lines[1:]]
    return "\n".join(indented_lines)


def convert_date(date_iso):
    try:
        date_obj = datetime.strptime(date_iso, "%Y-%m-%dT%H:%M:%SZ")
        return date_obj.strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return "Неверный формат даты"


def send_transactions(chat_id, access_token):
    transactions = get_transactions(access_token)

    if transactions:
        transactions_list = process_transactions(transactions)
        if transactions_list:
            formatted_transactions = "\n\n".join(transactions_list)
            chunks = split_text(formatted_transactions, 3000)
            for chunk in chunks:
                for attempt in range(3):
                    try:
                        reply = f"```\n{chunk}\n```"
                        bot.send_message(chat_id, f"{reply}", parse_mode="Markdown")
                        break
                    except Exception as e:
                        print(f"Ошибка отправки сообщения, попытка {attempt + 1}: {str(e)}")
                        time.sleep(5)
        else:
            print("Нет новых транзакций на сегодня.")
    else:
        print("Нет транзакций на сегодня.")


def split_text(text, max_length):
    """Функция для разбивки текста на части, не превышающие max_length символов."""
    return [text[i:i + max_length] for i in range(0, len(text), max_length)]


def periodic_statement_request():
    chat_id = CHAT_ID
    while True:
        time.sleep(180)
        try:
            access_token = token_manager.get_access_token()
            send_transactions(chat_id, access_token)
        except Exception as e:
            print(f"Ошибка при запросе выписки: {str(e)}")


token_manager = None


def check_user(message):
    return message.from_user.id in ALLOWED_USERS


def token_update():
    while True:
        time.sleep(60)
        try:
            token_manager.get_access_token()
        except Exception as e:
            print(f"Ошибка обновления токена: {str(e)}")


def process_auth_code(auth_code):
    global token_manager
    try:
        token_manager = TokenManager(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, CERT_FILE, KEY_FILE)
        token_manager.get_tokens(auth_code)
        print("Токены успешно получены.")
        threading.Thread(target=token_update).start()
        threading.Thread(target=periodic_statement_request).start()
    except Exception as e:
        print(f"Ошибка при обработке кода авторизации: {str(e)}")


@bot.message_handler(commands=['auth'])
def authenticate(message):
    if not check_user(message):
        bot.reply_to(message, "У вас нет доступа к этой команде.")
        return

    global token_manager
    try:
        auth_code = message.text.split(" ")[1]
        token_manager = TokenManager(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, CERT_FILE, KEY_FILE)
        token_manager.get_tokens(auth_code)
        bot.reply_to(message, "Токены успешно получены.")
        threading.Thread(target=token_update).start()
        threading.Thread(target=periodic_statement_request).start()
    except IndexError:
        bot.reply_to(message, "Пожалуйста, укажите код авторизации.")
    except Exception as e:
        bot.reply_to(message, f"Ошибка: {str(e)}")


@bot.message_handler(commands=['get_transactions'])
def get_transactions_for_date(message):
    if not check_user(message):
        bot.reply_to(message, "У вас нет доступа к этой команде.")
        return

    try:
        date_str = message.text.split(" ")[1]  # ожидаем формат DD-MM-YYYY
        # Проверяем, соответствует ли дата формату
        date_obj = datetime.strptime(date_str, "%d-%m-%Y")  # это выбросит ValueError, если дата неверна
        formatted_date = date_obj.strftime("%Y-%m-%d")  # преобразуем в формат YYYY-MM-DD

        access_token = token_manager.get_access_token()
        transactions = get_transactions_by_date(access_token, formatted_date)

        if transactions:
            transactions_list = process_transactions(transactions)
            if transactions_list:
                formatted_transactions = "\n\n".join(transactions_list)
                chunks = split_text(formatted_transactions, 3000)
                for chunk in chunks:
                    reply = f"```\n{chunk}\n```"
                    bot.send_message(message.chat.id, f"{reply}", parse_mode="Markdown")
            else:
                bot.reply_to(message, "Нет новых транзакций за эту дату.")
        else:
            bot.reply_to(message, "Нет транзакций за эту дату.")

    except IndexError:
        bot.reply_to(message, "Пожалуйста, укажите дату в формате DD-MM-YYYY.")
    except ValueError:
        bot.reply_to(message, "Неверный формат даты. Пожалуйста, используйте формат DD-MM-YYYY.")
    except Exception as e:
        bot.reply_to(message, f"Ошибка: {str(e)}")

def get_transactions_by_date(access_token, date_str):
    account_number = ACCOUNT_NUMBER
    url_get_transactions = URL_GET_TRANSACTIONS
    url = f"{url_get_transactions}?accountNumber={account_number}&statementDate={date_str}&page=1&curFormat=curTransfer"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, cert=(CERT_FILE, KEY_FILE), headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            transactions = response.json().get('transactions', [])
            return [t for t in transactions if t.get('direction') == 'CREDIT']
        else:
            print(f"Ошибка получения транзакций: {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса транзакций: {str(e)}")
        return []


@app.route('/redirect/')
def redirect_handler():
    code = request.args.get('code')
    if code:
        process_auth_code(code)
        print(code)
        return "Код успешно получен.", 200
    else:
        return "Код не найден.", 400


def start_bot_polling():
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            print(f"Ошибка в процессе работы бота: {str(e)}")
            time.sleep(5)


if __name__ == '__main__':
    threading.Thread(target=start_bot_polling).start()
    app.run(host='0.0.0.0', port=5000)

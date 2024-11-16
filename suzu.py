#!/usr/bin/python3

"""
Скрипт для автоматизации запуска различных модулей:
- kyocera: управление и извлечение данных из устройств Kyocera
- gowitness: автоматизированное создание снимков веб-сайтов
- seth: MITM атака на множественные узлы в подсети с использованием RDP
- kerberoasting: извлечение Kerberos хэшей для дальнейшего анализа
- asreproasting: получение хэшей для AS-REQ атак на пользователей
- nmap_canvas: сканирование сети с визуализацией результатов
- printnightmare: эксплуатация уязвимости PrintNightmare
- web: запуск локального веб-сервера для взаимодействия с данными

Авторы: @suzu
"""

# ====================================================================
# Импорты
# ====================================================================

import argparse
import subprocess
import sys
import warnings
from colorama import init

# ====================================================================
# Настройка цветового вывода и подавления предупреждений
# ====================================================================

init(autoreset=True)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)



# ====================================================================
# Классы модулей
# ====================================================================

class KyoceraModule:
    """Класс для управления модулем Kyocera."""

    def __init__(self, interface=None, subnet=None):
        self.interface = interface
        self.subnet = subnet

    def show(self):
        subprocess.run(['python3', 'kyocera.py', 'show'])

    def clear(self):
        subprocess.run(['python3', 'kyocera.py', 'clear'])

    def scan(self):
        if self.interface and self.subnet:
            subprocess.run(['python3', 'kyocera.py', 'scan', '-i', self.interface, '-s', self.subnet])


class GoWitnessModule:
    """Класс для управления модулем GoWitness."""

    def __init__(self, interface, subnet):
        self.interface = interface
        self.subnet = subnet

    def run(self):
        subprocess.run(['python3', 'gowitness.py', '-i', self.interface, '-s', self.subnet])


class SethModule:
    """Класс для управления модулем SETH для MITM-атак."""

    def __init__(self, interface=None, subnet=None, server=None):
        self.interface = interface
        self.subnet = subnet
        self.server = server

    def mitm(self):
        if self.interface and self.subnet and self.server:
            subprocess.run(['python3', 'suzu_seth.py', 'mitm', '-i', self.interface, '-s', self.subnet, '-r', self.server])

    def show(self):
        subprocess.run(['python3', 'suzu_seth.py', 'show'])

    def clear(self):
        subprocess.run(['python3', 'suzu_seth.py', 'clear'])


class KerberoastingModule:
    """Класс для управления модулем Kerberoasting."""

    def __init__(self, ip, username, credentials, domain, wordlist='/usr/share/wordlists/rockyou.txt'):
        self.ip = ip
        self.username = username
        self.credentials = credentials
        self.domain = domain
        self.wordlist = wordlist

    def run(self):
        subprocess.run(['python3', 'kerberoasting.py', self.ip, '-u', self.username, '-c', self.credentials, '-d', self.domain, '-w', self.wordlist])


class AsreproastingModule:
    """Класс для управления модулем Asreproasting."""

    def __init__(self, dc_ip, domain, usersfile=None, username=None, credentials=None, wordlist='/usr/share/wordlists/rockyou.txt'):
        self.dc_ip = dc_ip
        self.domain = domain
        self.usersfile = usersfile
        self.username = username
        self.credentials = credentials
        self.wordlist = wordlist

    def run(self):
        args = ['python3', 'asreproasting.py', self.dc_ip, '-d', self.domain, '-w', self.wordlist]
        if self.usersfile:
            args.extend(['-f', self.usersfile])
        elif self.username and self.credentials:
            args.extend(['-u', self.username, '-c', self.credentials])
        subprocess.run(args)


class NmapCanvasModule:
    """Класс для управления модулем Nmap Canvas."""

    def __init__(self, subnet):
        self.subnet = subnet

    def run(self):
        subprocess.run(['python3', 'nmap_canvas.py', '-s', self.subnet])


class WebModule:
    """Класс для управления запуском веб-сервера."""

    @staticmethod
    def run():
        subprocess.run(['python3', 'web.py'])


class PrintNightmareModule:
    """Класс для управления модулем PrintNightmare."""

    def __init__(self, subnet, username, credentials, action, interface=None, new_username=None, new_password=None):
        self.subnet = subnet
        self.username = username
        self.credentials = credentials
        self.action = action
        self.interface = interface
        self.new_username = new_username
        self.new_password = new_password

    def run(self):
        command = ['python3', 'printnightmare.py', '-s', self.subnet, '-u', self.username, '-c', self.credentials]
        command.append('-check' if self.action == 'check' else '-exploit')

        # Добавляем дополнительные параметры, если они указаны
        if self.interface:
            command.extend(['-i', self.interface])
        if self.new_username:
            command.extend(['-new-username', self.new_username])
        if self.new_password:
            command.extend(['-new-password', self.new_password])

        subprocess.run(command)


class SSHModule:
    """Класс для управления модулем SSH."""

    def __init__(self, subnet, credentials_file=None, users_file=None, passwords_file=None):
        self.subnet = subnet
        self.credentials_file = credentials_file
        self.users_file = users_file
        self.passwords_file = passwords_file

    def run(self):
        """Запуск модуля SSH."""
        command = ['python3', 'ssh.py', '-s', self.subnet]
        if self.credentials_file:
            command.extend(['-f', self.credentials_file])
        if self.users_file and self.passwords_file:
            command.extend(['-u', self.users_file, '-p', self.passwords_file])
        subprocess.run(command)

# ====================================================================
# Основная функция
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description='Скрипт для автоматизации запуска различных модулей')
    subparsers = parser.add_subparsers(dest='script', help='Выбор модуля для запуска')

    # Kyocera parser
    parser_kyocera = subparsers.add_parser('kyocera', help='Запуск модуля KYOCERA')
    kyocera_subparsers = parser_kyocera.add_subparsers(dest='command', help='Доступные команды')
    kyocera_subparsers.add_parser('show', help='Показать содержимое таблицы kyocera')
    kyocera_subparsers.add_parser('clear', help='Очистить содержимое таблицы kyocera')
    scan_parser = kyocera_subparsers.add_parser('scan', help='Сканирование подсети и извлечение данных')
    scan_parser.add_argument('-i', '--interface', required=True, help='Сетевой интерфейс')
    scan_parser.add_argument('-s', '--subnet', required=True, help='Подсеть или одиночный IP-адрес для сканирования')

    # GoWitness parser
    parser_gowitness = subparsers.add_parser('gowitness', help='Запуск модуля GOWITNESS')
    parser_gowitness.add_argument('-i', '--interface', required=True, help='Сетевой интерфейс')
    parser_gowitness.add_argument('-s', '--subnet', required=True, help='Подсеть или одиночный IP-адрес для сканирования')

    # SETH parser
    parser_seth = subparsers.add_parser('seth', help='Запуск модуля SETH для MITM-атак')
    seth_subparsers = parser_seth.add_subparsers(dest='command', help='Доступные команды')
    seth_subparsers.add_parser('show', help='Вывод всех паролей')
    seth_subparsers.add_parser('clear', help='Очистка базы данных')
    mitm_parser = seth_subparsers.add_parser('mitm', help='MITM атака на множественные узлы в подсети')
    mitm_parser.add_argument('-i', '--interface', required=True, help="Сетевой интерфейс")
    mitm_parser.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP-адрес для прослушивания")
    mitm_parser.add_argument('-r', '--server', required=True, help="RDP сервер")

    # Kerberoasting parser
    parser_kerberoasting = subparsers.add_parser('kerberoasting', help='Запуск модуля KERBEROASTING')
    parser_kerberoasting.add_argument('ip', help="IP-адрес контроллера домена")
    parser_kerberoasting.add_argument('-u', '--username', required=True, help="Имя пользователя")
    parser_kerberoasting.add_argument('-c', '--credentials', required=True, help="Пароль или NT-hash")
    parser_kerberoasting.add_argument('-d', '--domain', required=True, help="Домен")
    parser_kerberoasting.add_argument('-w', '--wordlist', default='/usr/share/wordlists/rockyou.txt', help="Путь к словарю")

    # Asreproasting parser
    parser_asreproasting = subparsers.add_parser('asreproasting', help='Запуск модуля ASREPROASTING')
    parser_asreproasting.add_argument('dc_ip', help="IP-адрес контроллера домена")
    parser_asreproasting.add_argument('-d', '--domain', required=True, help="Домен")
    parser_asreproasting.add_argument('-f', '--usersfile', help="Файл с пользователями")
    parser_asreproasting.add_argument('-u', '--username', help="Имя пользователя")
    parser_asreproasting.add_argument('-c', '--credentials', help="Пароль или NT-hash")
    parser_asreproasting.add_argument('-w', '--wordlist', default="/usr/share/wordlists/rockyou.txt", help="Путь к словарю")

    # Nmap Canvas parser
    parser_nmap_canvas = subparsers.add_parser('nmap_canvas', help='Запуск модуля NmapCanvas')
    parser_nmap_canvas.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP-адрес для сканирования")

    # Web Server parser
    subparsers.add_parser('web', help='Запуск локального веб-сервера')

    # PrintNightmare parser
    parser_printnightmare = subparsers.add_parser('printnightmare', help='Запуск модуля PrintNightmare')
    parser_printnightmare.add_argument('-s', '--subnet', required=True, help='IP-адрес или подсеть для сканирования')
    parser_printnightmare.add_argument('-u', '--username', required=True, help='Имя пользователя для аутентификации')
    parser_printnightmare.add_argument('-c', '--credentials', required=True, help='Пароль или NT-хэш для аутентификации')

    # Дополнительные аргументы для эксплуатации
    parser_printnightmare.add_argument('-i', '--interface', help='Сетевой интерфейс (только для exploit)')
    parser_printnightmare.add_argument('-new-username', help='Имя нового пользователя для эксплуатации (только для exploit)')
    parser_printnightmare.add_argument('-new-password', help='Пароль нового пользователя для эксплуатации (только для exploit)')

    # Группа действий: проверка или эксплуатация
    action_group = parser_printnightmare.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-check', action='store_true', help='Проверка наличия уязвимости')
    action_group.add_argument('-exploit', action='store_true', help='Эксплуатация уязвимости')

    # SSH parser
    parser_ssh = subparsers.add_parser('ssh', help='Запуск модуля SSH')
    parser_ssh.add_argument('-s', '--subnet', required=True, help="Подсеть для сканирования.")
    parser_ssh.add_argument('-f', '--credentials_file', help="Файл с парами username:password.")
    parser_ssh.add_argument('-u', '--users_file', help="Файл с логинами.")
    parser_ssh.add_argument('-p', '--passwords_file', help="Файл с паролями.")

    args = parser.parse_args()

    if args.script == 'kyocera':
        module = KyoceraModule(args.interface, args.subnet)
        getattr(module, args.command)()
    elif args.script == 'gowitness':
        GoWitnessModule(args.interface, args.subnet).run()
    elif args.script == 'seth':
        if args.command == 'mitm':
            module = SethModule(args.interface, args.subnet, args.server)
            getattr(module, args.command)()
        elif args.command == 'clear':
            module = SethModule()
            getattr(module, args.command)()
        elif args.command == 'show':
            module = SethModule()
            getattr(module, args.command)()
    elif args.script == 'kerberoasting':
        KerberoastingModule(args.ip, args.username, args.credentials, args.domain, args.wordlist).run()
    elif args.script == 'asreproasting':
        AsreproastingModule(args.dc_ip, args.domain, args.usersfile, args.username, args.credentials, args.wordlist).run()
    elif args.script == 'nmap_canvas':
        NmapCanvasModule(args.subnet).run()
    elif args.script == 'web':
        WebModule.run()
    elif args.script == 'printnightmare':
        action = 'check' if args.check else 'exploit'
        PrintNightmareModule(
            args.subnet, args.username, args.credentials, action,
            interface=args.interface,
            new_username=args.new_username,
            new_password=args.new_password
        ).run()
    elif args.script == 'ssh':
        SSHModule(args.subnet, args.credentials_file, args.users_file, args.passwords_file).run()

if __name__ == '__main__':
    main()

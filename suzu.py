import argparse
import subprocess
import sys

def run_kyocera(interface, subnet):
    subprocess.run(['python3', 'suzu_kyocera.py', '-i', interface, '-s', subnet])

def run_gowitness(interface, subnet):
    subprocess.run(['python3', 'suzu_gowitness.py', '-i', interface, '-s', subnet])

def run_seth(command, interface=None, subnet=None, server=None, ip_address=None):
    if command == 'mitm':
        subprocess.run(['python3', 'suzu_seth.py', 'mitm', '-i', interface, '-s', subnet, '-r', server])
    elif command == 'show':
        subprocess.run(['python3', 'suzu_seth.py', 'show'])
    elif command == 'clear':
        subprocess.run(['python3', 'suzu_seth.py', 'clear'])
    elif command == 'remove':
        subprocess.run(['python3', 'suzu_seth.py', 'remove', ip_address])

def main():
    parser = argparse.ArgumentParser(description='Скрипт для автоматизации запуска доступных модулей')
    
    subparsers = parser.add_subparsers(dest='script', help='Выбор скрипта для запуска')

    # Kyocera parser
    parser_kyocera = subparsers.add_parser('kyocera', help='Запуск модуля KYOCERA')
    parser_kyocera.add_argument('-i', '--interface', required=True, help='Сетевой интерфейс')
    parser_kyocera.add_argument('-s', '--subnet', required=True, help='Подсеть или одиночный IP для сканирования')

    # GoWitness parser
    parser_gowitness = subparsers.add_parser('gowitness', help='Запуск модуля GOWITNESS')
    parser_gowitness.add_argument('-i', '--interface', required=True, help='Сетевой интерфейс')
    parser_gowitness.add_argument('-s', '--subnet', required=True, help='Подсеть или одиночный IP для сканирования')

    # SETH parser
    parser_seth = subparsers.add_parser('seth', help='Запуск модуля SETH')
    seth_subparsers = parser_seth.add_subparsers(dest='command', help='Доступные команды')

    mitm_parser = seth_subparsers.add_parser('mitm', help='Запуск SETH на указанную подсеть')
    mitm_parser.add_argument('-i', '--interface', required=True, help="Сетевой интерфейс")
    mitm_parser.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP для прослушивания")
    mitm_parser.add_argument('-r', '--server', required=True, help="RDP сервер")

    seth_subparsers.add_parser('show', help='Вывод всех паролей')
    seth_subparsers.add_parser('clear', help='Очистка базы данных')

    remove_parser = seth_subparsers.add_parser('remove', help='Удаление определенного IP-адреса')
    remove_parser.add_argument('ip', help="IP-адрес для удаления")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.script == 'kyocera':
        if not args.interface or not args.subnet:
            parser_kyocera.print_help(sys.stderr)
        else:
            run_kyocera(args.interface, args.subnet)
    elif args.script == 'gowitness':
        if not args.interface or not args.subnet:
            parser_gowitness.print_help(sys.stderr)
        else:
            run_gowitness(args.interface, args.subnet)
    elif args.script == 'seth':
        if args.command is None:
            parser_seth.print_help(sys.stderr)
        elif args.command == 'mitm':
            if not args.interface or not args.subnet or not args.server:
                mitm_parser.print_help(sys.stderr)
            else:
                run_seth(args.command, args.interface, args.subnet, args.server)
        elif args.command == 'show':
            run_seth(args.command)
        elif args.command == 'clear':
            run_seth(args.command)
        elif args.command == 'remove':
            if not args.ip:
                remove_parser.print_help(sys.stderr)
            else:
                run_seth(args.command, ip_address=args.ip)

if __name__ == '__main__':
    main()


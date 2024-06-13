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

def run_kerberoasting(ip, username, credentials, domain, wordlist):
    subprocess.run(['python3', 'suzu_kerberoasting.py', ip, '-u', username, '-c', credentials, '-d', domain, '-w', wordlist])

def run_asreproasting(dc_ip, domain, usersfile=None, username=None, credentials=None, wordlist="/usr/share/wordlists/rockyou.txt"):
    args = ['python3', 'suzu_asreproasting.py', dc_ip, '-d', domain, '-w', wordlist]

    if usersfile:
        args.extend(['-f', usersfile])
    elif username and credentials:
        args.extend(['-u', username, '-c', credentials])

    subprocess.run(args)

def main():
    parser = argparse.ArgumentParser(description='Script for automating available modules')

    subparsers = parser.add_subparsers(dest='script', help='Choose script to execute')

    # Kyocera parser
    parser_kyocera = subparsers.add_parser('kyocera', help='Run KYOCERA module')
    parser_kyocera.add_argument('-i', '--interface', required=True, help='Network interface')
    parser_kyocera.add_argument('-s', '--subnet', required=True, help='Subnet or single IP to scan')

    # GoWitness parser
    parser_gowitness = subparsers.add_parser('gowitness', help='Run GOWITNESS module')
    parser_gowitness.add_argument('-i', '--interface', required=True, help='Network interface')
    parser_gowitness.add_argument('-s', '--subnet', required=True, help='Subnet or single IP to scan')

    # SETH parser
    parser_seth = subparsers.add_parser('seth', help='Run SETH module')
    seth_subparsers = parser_seth.add_subparsers(dest='command', help='Available commands')

    mitm_parser = seth_subparsers.add_parser('mitm', help='Run SETH in MITM mode')
    mitm_parser.add_argument('-i', '--interface', required=True, help="Network interface")
    mitm_parser.add_argument('-s', '--subnet', required=True, help="Subnet or single IP to listen on")
    mitm_parser.add_argument('-r', '--server', required=True, help="RDP server")

    seth_subparsers.add_parser('show', help='Show all passwords')
    seth_subparsers.add_parser('clear', help='Clear the database')

    remove_parser = seth_subparsers.add_parser('remove', help='Remove specific IP address')
    remove_parser.add_argument('ip', help="IP address to remove")

    # Kerberoasting parser
    parser_kerberoasting = subparsers.add_parser('kerberoasting', help='Run KERBEROASTING module')
    parser_kerberoasting.add_argument('ip', help="Domain controller IP address")
    parser_kerberoasting.add_argument('-u', '--username', required=True, help="Username")
    parser_kerberoasting.add_argument('-c', '--credentials', required=True, help="Password or NT-hash")
    parser_kerberoasting.add_argument('-d', '--domain', required=True, help="Domain")
    parser_kerberoasting.add_argument('-w', '--wordlist', default='/usr/share/wordlists/rockyou.txt', help="Path to wordlist file")

    # Asreproasting parser
    parser_asreproasting = subparsers.add_parser('asreproasting', help='Run ASREPROASTING module')
    parser_asreproasting.add_argument('dc_ip', type=str, help="Domain controller IP address")
    parser_asreproasting.add_argument('-d', '--domain', type=str, required=True, help="Domain")
    parser_asreproasting.add_argument('-f', '--usersfile', type=str, help="File with users")
    parser_asreproasting.add_argument('-u', '--username', type=str, help="Username")
    parser_asreproasting.add_argument('-c', '--credentials', type=str, help="Password or NT-hash")
    parser_asreproasting.add_argument('-w', '--wordlist', type=str, default="/usr/share/wordlists/rockyou.txt", help="Path to wordlist")

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
    elif args.script == 'kerberoasting':
        if not args.ip or not args.username or not args.credentials or not args.domain:
            parser_kerberoasting.print_help(sys.stderr)
        else:
            run_kerberoasting(args.ip, args.username, args.credentials, args.domain, args.wordlist)
    elif args.script == 'asreproasting':
        if args.username or args.credentials:
            if args.usersfile:
                parser_asreproasting.error("-f/--usersfile нельзя использовать с -u/--username или -c/--credentials")
            elif not (args.username and args.credentials):
                parser_asreproasting.error("-u/--username и -c/--credentials должны быть использованы вместе")

        if not args.dc_ip or not args.domain:
            parser_asreproasting.print_help(sys.stderr)
        else:
            run_asreproasting(args.dc_ip, args.domain, args.usersfile, args.username, args.credentials, args.wordlist)


if __name__ == '__main__':
    main()

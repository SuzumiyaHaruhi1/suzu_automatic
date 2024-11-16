# -*- coding: utf-8 -*-
"""
NmapCanvas - инструмент для сетевого сканирования TCP/UDP портов с сохранением 
результатов в базу данных и в формате Canvas.

Автор: @suzu

Использование:
    python3 nmap_canvas.py -s <подсеть или IP>
"""

import os
import sys
import json
import sqlite3
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import nmap
import uuid


class NmapDatabaseManager:
    """Класс для управления базой данных SQLite3 для сохранения результатов."""
    def __init__(self, db_path='suzu.db'):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        """Создает таблицу ports, если она отсутствует."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nmap (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                description TEXT,
                state TEXT,
                date_added TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def save_port(self, ip, port, protocol, service, description, state):
        """
        Сохраняет данные о порте в базу данных.

        :param ip: IP-адрес
        :param port: Номер порта
        :param protocol: Протокол (TCP/UDP)
        :param service: Имя сервиса
        :param description: Описание
        :param state: Состояние порта
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO nmap (ip, port, protocol, service, description, state, date_added)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip, port, protocol, service, description, state, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()


class NmapCanvas:
    """Класс для выполнения сетевого сканирования и сохранения результатов."""
    def __init__(self, db_manager):
        self.top_tcp_ports = [
            21, 22, 23, 25, 53, 67, 68, 69, 80, 123, 137, 161, 443, 445, 514, 1433, 1540,
            1541, 1545, 1900, 3389, 4786, 8080, 8443, 9998, 9999, 13000, 13292, 14000
        ]
        self.top_udp_ports = [53, 67, 68, 69, 123, 137, 161, 500, 514, 1900]
        self.nm = nmap.PortScanner()
        self.subnet = None
        self.results = []
        self.db_manager = db_manager

    def parse_args(self):
        """Парсит аргументы командной строки для получения IP или подсети."""
        parser = argparse.ArgumentParser(description="Сканирование сети и сохранение результатов.")
        parser.add_argument('-s', '--subnet', required=True, help="Подсеть или IP для сканирования")
        args = parser.parse_args()
        self.subnet = args.subnet

    def _generate_id(self):
        """Генерирует уникальный идентификатор для узла или ребра Canvas."""
        return str(uuid.uuid4())

    def nmap_scan(self, ip, port_type):
        """
        Выполняет сканирование TCP/UDP портов и сохраняет результаты в базу данных и для Canvas.

        :param ip: IP-адрес
        :param port_type: Тип порта ('tcp' или 'udp')
        """
        ports = self.top_tcp_ports if port_type == 'tcp' else self.top_udp_ports
        scan_type = '-sV' if port_type == 'tcp' else '-sU'
        self.nm.scan(ip, arguments=f'{scan_type} -p {",".join(map(str, ports))}')

        port_descriptions = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP сервер", 68: "DHCP клиент",
            69: "TFTP", 80: "HTTP", 123: "NTP", 137: "NetBIOS", 161: "SNMP", 443: "HTTPS", 445: "SMB",
            514: "Syslog", 1433: "Microsoft SQL Server", 1540: "1С Агент", 1541: "1С Менеджер", 1545: "1С Сервер",
            1900: "SSDP", 3389: "RDP", 4786: "Cisco Smart Install", 8080: "HTTP (альтернативный)",
            8443: "HTTPS (альтернативный)", 9998: "MaxPatrol агент", 9999: "MaxPatrol уязвимости",
            13000: "KSC Агент", 13292: "KSC Администрирование", 14000: "KSC Компоненты"
        }

        ports_data = []
        for proto in self.nm[ip].all_protocols():
            for port in self.nm[ip][proto]:
                port_info = self.nm[ip][proto][port]
                if port_info['state'] == 'open':
                    service = port_info['name']
                    description = port_descriptions.get(port, "Неизвестный сервис")
                    state = port_info['state']
                    self.db_manager.save_port(ip, port, proto, service, description, state)
                    ports_data.append({
                        "host": ip,
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "description": description,
                        "state": state
                    })
        self.results.extend(ports_data)

    def convert_canvas(self):
        """
        Преобразует результаты сканирования в формат JSON для Canvas и сохраняет данные в файл.
        """
        # Группируем данные по хостам
        grouped_results = {}
        for entry in self.results:
            host = entry['host']
            if host not in grouped_results:
                grouped_results[host] = []
            grouped_results[host].append(entry)

        canvas_data = {
            "nodes": [],
            "edges": []
        }
        y_position = -260  # Начальная координата для вертикального расположения узлов

        for host, ports in grouped_results.items():
            host_id = self._generate_id()

            # Добавляем узел для хоста
            canvas_data["nodes"].append({
                "id": host_id,
                "x": -200,
                "y": y_position + (len(ports) - 1) * 50 + 90,
                "width": 250,
                "height": 80,
                "type": "text",
                "text": host,
                "color": "5"
            })

            y_position += 100  # Сдвиг по оси Y для следующего узла

            for port_info in ports:
                port_id = self._generate_id()
                # Добавляем узел для порта
                canvas_data["nodes"].append({
                    "id": port_id,
                    "x": 180,
                    "y": y_position,
                    "width": 250,
                    "height": 60,
                    "type": "text",
                    "text": f'{port_info["port"]}/{port_info["protocol"]} | {port_info["service"]}'
                })
                # Добавляем связь между хостом и портом
                canvas_data["edges"].append({
                    "id": self._generate_id(),
                    "fromNode": host_id,
                    "fromSide": "right",
                    "toNode": port_id,
                    "toSide": "left"
                })
                y_position += 100  # Обновление позиции для следующего порта

        # Сохранение JSON-файла Canvas
        os.makedirs('results/nmap', exist_ok=True)
        canvas_output = f'results/nmap/nmap_canvas_{self.subnet.replace("/", "_")}.canvas'
        with open(canvas_output, 'w') as f:
            json.dump(canvas_data, f, indent=4, ensure_ascii=False)
        print(f'Результаты сохранены в ./{canvas_output}')


    def scan_ip(self, ip):
        """Сканирует TCP и UDP порты для указанного IP и сохраняет результаты."""
        self.nmap_scan(ip, 'tcp')
        self.nmap_scan(ip, 'udp')


def main():
    """Запускает процесс сканирования в многопоточном режиме и сохраняет результаты."""
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    db_manager = NmapDatabaseManager()
    nmap_canvas = NmapCanvas(db_manager)
    nmap_canvas.parse_args()

    ips = [str(ip) for ip in ipaddress.IPv4Network(nmap_canvas.subnet)]
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(nmap_canvas.scan_ip, ips)

    nmap_canvas.convert_canvas()
    print("Сканирование завершено. Результаты сохранены в базе данных 'suzu.db' и файле Canvas.")


if __name__ == "__main__":
    main()

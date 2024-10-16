import os
import sys
import json
import uuid
import ipaddress
import argparse
import nmap
from concurrent.futures import ThreadPoolExecutor

class NmapCanvas:
    def __init__(self):
        """
        Инициализация класса, определение портов и подготовка объекта Nmap для сканирования.
        """
        self.top_tcp_ports = [21, 22, 23, 25, 53, 80, 81, 88, 443, 445, 1433, 1540, 1541, 1545, 3389, 4786, 8080, 8443]
        self.top_udp_ports = [53, 67, 68, 69, 123, 137, 161, 500, 514, 1900]
        self.nm = nmap.PortScanner()  # Инициализация nmap сканера
        self.subnet = None  # Переменная для хранения подсети или IP
        self.results = []  # Список для хранения результатов сканирования

    def parse_args(self):
        """
        Парсинг аргументов командной строки для получения подсети или IP адреса.
        """
        parser = argparse.ArgumentParser(description="Определение сервисов на портах и создание canvas схемы")
        parser.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP для сканирования")
        args = parser.parse_args()
        self.subnet = args.subnet

    def nmap_scan(self, ip, port_type):
        """
        Выполняет сканирование TCP или UDP портов указанного IP адреса.
        :param ip: IP адрес для сканирования
        :param port_type: Тип порта ('tcp' или 'udp')
        :return: Список данных об открытых портах
        """
        ports = self.top_tcp_ports if port_type == 'tcp' else self.top_udp_ports
        scan_type = '-sV' if port_type == 'tcp' else '-sU'  # Выбор типа сканирования
        self.nm.scan(ip, arguments=f'{scan_type} -p {",".join(map(str, ports))}')
        
        ports_data = []  # Список для хранения данных об открытых портах
        for proto in self.nm[ip].all_protocols():
            for port in self.nm[ip][proto].keys():
                if self.nm[ip][proto][port]['state'] == 'open':  # Проверка состояния порта
                    ports_data.append({
                        "port": f'{port}/{proto}',
                        "service": self.nm[ip][proto][port]['name']
                    })
        return ports_data

    def scan_ip(self, ip):
        """
        Сканирует указанный IP адрес (как TCP, так и UDP порты).
        :param ip: IP адрес для сканирования
        """
        tcp_ports = self.nmap_scan(ip, 'tcp')  # Сканирование TCP портов
        udp_ports = self.nmap_scan(ip, 'udp')  # Сканирование UDP портов

        combined_ports = tcp_ports + udp_ports  # Объединение результатов сканирования

        host_data = {
            "host": ip,
            "ports": combined_ports
        }

        self.results.append(host_data)  # Добавление данных о хосте в результаты

    def convert_canvas(self):
        """
        Конвертирует результаты сканирования в формат JSON и создает canvas схему.
        """
        # Сортировка результатов по IP адресам
        self.results = sorted(self.results, key=lambda x: ipaddress.ip_address(x['host']))

        canvas_data = {
            "nodes": [],
            "edges": []
        }

        def generate_id():
            """
            Генерация уникального идентификатора для узлов и ребер.
            :return: Уникальный идентификатор
            """
            return str(uuid.uuid4()).replace('-', '')

        # Инициализация начальных координат для узлов
        y_position = -260
        y_increment = 100

        for host in self.results:
            if not host["ports"]:
                continue

            host_id = generate_id()
            canvas_data["nodes"].append({
                "id": host_id,
                "x": -200,
                "y": y_position + (len(host["ports"]) - 1) * 50 + 90,
                "width": 250,
                "height": 80,
                "type": "text",
                "text": host["host"],
                "color": "5"
            })

            y_position += y_increment

            # Создание узлов и ребер для каждого порта
            for port_info in host["ports"]:
                port_id = generate_id()
                canvas_data["nodes"].append({
                    "id": port_id,
                    "x": 180,
                    "y": y_position,
                    "width": 250,
                    "height": 60,
                    "type": "text",
                    "text": f'{port_info["port"]} | {port_info["service"]}'
                })

                # Связывание узлов с ребрами
                canvas_data["edges"].append({
                    "id": generate_id(),
                    "fromNode": host_id,
                    "fromSide": "right",
                    "toNode": port_id,
                    "toSide": "left"
                })

                y_position += y_increment

        # Сохранение результатов в файл canvas
        os.makedirs('results/nmap', exist_ok=True)
        canvas_output = f'results/nmap/nmap_canvas_{self.subnet.replace("/", "_")}.canvas'
        with open(canvas_output, 'w') as canvas_file:
            json.dump(canvas_data, canvas_file, indent=4)

        print(f'Результаты сканирования сохранены в ./{canvas_output}')

if __name__ == "__main__":
    # Проверка прав root
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)

    # Создание экземпляра NmapCanvas и запуск сканирования
    nmap_canvas = NmapCanvas()
    nmap_canvas.parse_args()

    # Генерация списка IP адресов из подсети
    ips = [str(ip) for ip in ipaddress.IPv4Network(nmap_canvas.subnet)]

    # Параллельное сканирование IP адресов
    with ThreadPoolExecutor(max_workers=1000) as executor:
        for ip in ips:
            executor.submit(nmap_canvas.scan_ip, ip)

    # Ждем завершения всех заданий
    executor.shutdown(wait=True)

    # Сохранение результатов в canvas формате
    nmap_canvas.convert_canvas()

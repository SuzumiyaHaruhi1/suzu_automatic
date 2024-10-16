import ipaddress
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import nmap
import argparse
import json


class NmapCanvas:
    def __init__(self):
        # Определение портов для сканирования сервисов (TCP и UDP)
        self.top_tcp_ports = [21, 22, 23, 25, 53, 80, 81, 88, 443, 445, 1540, 1541, 1545, 3389, 8080, 8443]
        self.top_udp_ports = [53, 67, 68, 69, 123, 137, 161, 500, 514, 1900]
        # Инициализация объекта сканера nmap
        self.nm = nmap.PortScanner()
        # Переменная для хранения подсети или IP адреса
        self.subnet = None
        # Список для хранения результатов сканирования
        self.results = []

    def parse_args(self):
        """
        Парсинг аргументов командной строки.
        """
        # Создание парсера аргументов
        parser = argparse.ArgumentParser(description="Определение сервисов на портах и создание canvas схемы")
        # Добавление аргумента для подсети или IP адреса
        parser.add_argument('-s', '--subnet', required=True, help="Подсеть или одиночный IP для сканирования")
        # Парсинг аргументов
        args = parser.parse_args()
        # Сохранение подсети или IP адреса
        self.subnet = args.subnet

    def nmap_scan(self, ip, port_type):
        """
        Выполняет сканирование TCP или UDP портов указанного IP адреса.

        :param ip: IP адрес для сканирования
        :param port_type: Тип порта ('tcp' или 'udp')
        :return: Список данных об открытых портах
        """
        # Определение портов и типа сканирования на основе типа порта
        if port_type == 'tcp':
            ports = self.top_tcp_ports
            scan_type = '-sV'  # Сканирование версии сервиса
        else:
            ports = self.top_udp_ports
            scan_type = '-sU'  # Сканирование UDP

        # Выполнение сканирования nmap с указанными параметрами
        self.nm.scan(ip, arguments=f'{scan_type} -p {",".join(map(str, ports))}')

        # Список для хранения данных об открытых портах
        ports_data = []
        # Проход по всем протоколам, обнаруженным на хосте
        for proto in self.nm[ip].all_protocols():
            ports = self.nm[ip][proto].keys()
            # Проход по всем портам указанного протокола
            for port in ports:
                port_info = self.nm[ip][proto][port]
                state = port_info['state']
                # Проверка состояния порта (если порт открыт)
                if state == 'open':
                    service = port_info['name']
                    # Добавление информации о порте в список
                    ports_data.append({
                        "port": f'{str(port)}/{proto}',
                        "service": service
                    })
        return ports_data

    def scan_ip(self, ip):
        """
        Сканирует указанный IP адрес.

        :param ip: IP адрес для сканирования
        """
        # Сканирование TCP портов
        tcp_ports = self.nmap_scan(ip, 'tcp')
        # Сканирование UDP портов
        udp_ports = self.nmap_scan(ip, 'udp')

        # Объединение результатов сканирования TCP и UDP портов
        combined_ports = tcp_ports + udp_ports

        # Формирование данных о хосте
        host_data = {
            "host": f"{str(ip).strip().replace('(', '').replace(')', '')}",
            "ports": combined_ports
        }

        # Добавление данных о хосте в общий список результатов
        self.results.append(host_data)

    def convert_canvas(self):
        """
        Конвертирует результаты сканирования в формат JSON и создает canvas схему.
        """
        # Конвертация результатов сканирования в формат JSON
        results_data = json.loads(json.dumps(self.results, indent=4))
        # Инициализация данных для canvas схемы
        canvas_data = {
            "nodes": [],
            "edges": []
        }

        def generate_id():
            """
            Генерирует уникальный идентификатор.

            :return: Уникальный идентификатор
            """
            import uuid
            return str(uuid.uuid4()).replace('-', '')

        # Создание узлов и ребер на основе данных Nmap
        y_position = -260  # Начальная y позиция для первого узла
        y_increment = 100  # Инкрементальная y позиция для каждого последующего узла
        for host in results_data:
            host_id = generate_id()
            # Создание узла для хоста
            if len(host["ports"]) == 0:
                continue
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

                # Создание узла для порта
                canvas_data["nodes"].append({
                    "id": port_id,
                    "x": 180,
                    "y": y_position,
                    "width": 250,
                    "height": 60,
                    "type": "text",
                    "text": f'{port_info["port"]} | {port_info["service"]}'
                })

                # Создание ребра между хостом и портом
                canvas_data["edges"].append({
                    "id": generate_id(),
                    "fromNode": host_id,
                    "fromSide": "right",
                    "toNode": port_id,
                    "toSide": "left"
                })

                y_position += y_increment

        # Сохранение данных canvas в файл
        os.makedirs('results/nmap', exist_ok=True)
        canvas_output = f'results/nmap/nmap_canvas.canvas'
        with open(canvas_output, 'w') as canvas_file:
            json.dump(canvas_data, canvas_file, indent=4)

        print(f'Результаты сканирования были сохранены в файл ./{canvas_output} в формате canvas')


if __name__ == "__main__":
    # Проверка прав пользователя, выполнение с sudo если не root
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', 'python3'] + sys.argv)
    nmap_canvas = NmapCanvas()

    # Парсинг аргументов командной строки
    nmap_canvas.parse_args()

    # Генерация списка IP адресов из подсети
    ips = [str(ip) for ip in ipaddress.IPv4Network(nmap_canvas.subnet)]
    
    # Параллельное выполнение сканирования IP адресов
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ips:
            executor.submit(nmap_canvas.scan_ip, ip)

    # Ждем завершения всех заданий
    executor.shutdown(wait=True)

    # Сохраняем результаты в формате canvas
    nmap_canvas.convert_canvas()

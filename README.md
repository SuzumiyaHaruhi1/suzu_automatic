# suzu
Скрипт предназначен для автоматизации выполнения ряда модулей:
- [x] [SETH](https://github.com/SySS-Research/Seth) для проведения MITM атаки с перехватом аутентификации пользователя на удаленном RDP-сервере.
- [x] KYOCERA для проверки IP-адресов из заданной подсети на наличие открытого порта 9091 и извлечения аутентификационных данных из адресной книги.
- [x] [GOWITNESS](https://github.com/sensepost/gowitness?tab=readme-ov-file) для проверки IP-адресов из заданной подсети на наличие открытых портов 80, 443, 8000, 8080 и создания скриншотов.
- [ ] KERBEROASTING для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования).
- [ ] ASREPROASTING для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования).
- [x] NMAP_CANVAS для скаинрования заданной подсети топ 10 портов tcp и udp и сохранения результата в формате canvas.
- [x] SSH для перебора паролей на диапазон.
- [ ] PRINTNIGHTMARE модуль для сканирования уязвимости PrintNightmare, а также ее эксплуатации. Имеется возможность добаления нового пользователя с паролем с помощью флагов.
## Зависимости
Перед запуском необходимо убедиться в наличии следующих библиотек:
- `psutil`
- `scapy`
- `tabulate`
- `colorama`
- `lxml`
- `nmap`

Команда для установки.
```python
pip install psutil scapy tabulate colorama lxml python-nmap
```
Также необходимо установить дополнительные модули, если они отсутствуют:
```bash
sudo apt install gowitness
```
```bash
pip install impacket
```
## Установка
```bash
git clone https://github.com/SuzumiyaHaruhi1/suzu_automatic.git
```
```bash
sudo chmod 755 suzu_automatic; cd suzu_automatic; chmod +x seth.sh
```
## HELP menu
```
Скрипт для автоматизации запуска различных модулей

positional arguments:
  {kyocera,gowitness,seth,kerberoasting,asreproasting,nmap_canvas,web,printnightmare,ssh}
                        Выбор модуля для запуска
    kyocera             Запуск модуля KYOCERA
    gowitness           Запуск модуля GOWITNESS
    seth                Запуск модуля SETH для MITM-атак
    kerberoasting       Запуск модуля KERBEROASTING
    asreproasting       Запуск модуля ASREPROASTING
    nmap_canvas         Запуск модуля NmapCanvas
    web                 Запуск локального веб-сервера
    printnightmare      Запуск модуля PrintNightmare
    ssh                 Запуск модуля SSH

optional arguments:
  -h, --help            show this help message and exit
  ```

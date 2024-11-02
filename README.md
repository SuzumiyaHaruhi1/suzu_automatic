# suzu
Скрипт предназначен для автоматизации выполнения ряда модулей:
- [x]  [SETH](https://github.com/SySS-Research/Seth) для проведения MITM атаки с перехватом аутентификации пользователя на удаленном RDP-сервере.
- [x]  KYOCERA для проверки IP-адресов из заданной подсети на наличие открытого порта 9091 и извлечения аутентификационных данных из адресной книги.
- [x]  [GOWITNESS](https://github.com/sensepost/gowitness?tab=readme-ov-file) для проверки IP-адресов из заданной подсети на наличие открытых портов 80, 443, 8000, 8080 и создания скриншотов.
- [ ]  KERBEROASTING для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования).
- [ ]  ASREPROASTING для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования).
- [x]  NMAP_CANVAS для скаинрования заданной подсети топ 10 портов tcp и udp и сохранения результата в формате canvas.
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
sudo chmod 755 suzu_automatic; cd suzu_automatic; chmod +x seth.sh; chmod 777 *
```
## Использование
Скрипт поддерживает несколько команд для различных задач. При запуске некоторых модулей происходит проверка прав пользователя и если запуск производится не от root, требуется ввести пароль.
### seth
#### mitm
Предназначен для запуска SETH на указанную подсеть для проведения MITM атаки.
```python
python3 suzu.py seth mitm -i <interface> -s <subnet> -r <rdp_server>
```
#### show
Предназначен для вывода всех имеющихся данных из таблицы `cleartext`, которая хранит в себе перехваченные пароли в чистом виде.
```python
python3 suzu.py seth show
```
#### clear
Предназначен для очистки всех таблиц базы данных.
```python
python3 suzu.py seth clear
```
#### remove
Предназначен для очистки значений (если существуют) для определенного IP-адреса (например, когда был перехвачен только NetNTLMv2 hash и требуется заново запустить SETH на этот IP-адрес).
```python
python3 suzu.py seth remove <IP-адрес>
```
### kyocera
```python
python3 suzu.py kyocera -i <interface> -s <subnet>
```
### gowitness
```python
python3 suzu.py gowitness -i <interface> -s <subnet>
```
### kerberoasting
```python
python3 suzu.py kerberoasting <dc_ip> -u <user> -c <password|nt_hash> -d <domain> [-w <wordlist>]
```
### asreproasting
#### С файлом
```python
python3 suzu.py asreproasting <dc_ip> -d <domain> -f <users_file> [-w <wordlist>]
```
#### С пользователем
```python
python3 suzu.py asreproasting <dc_ip> -d <domain> -u <username> -c <password|nt_hash> [-w <wordlist>]
```
### nmap canvas
Запускает nmap на ряд заданных портов tcp и udp. Можно поменять необходимые порты в коде `suzu_nmap_canvas.py`.

Полный перечень портов с описанием сервисов модно найти [здесь](https://developer.donnoval.ru/ports/).
```python
python3 suzu.py nmap_canvas -s <subnet>
```
## Демонстрация запуска скрипта
### seth
https://github.com/SuzumiyaHaruhi1/suzu_seth/assets/84810190/28ed97ee-1053-4d66-8737-72dc51892b7b

# suzu
Скрипт предназначен для автоматизации выполнения ряда модулей:
- [x]  [SETH](https://github.com/SySS-Research/Seth) для проведения MITM атаки с перехватом аутентификации пользователя на удаленном RDP-сервере.
- [x]  KYOCERA для проверки IP-адресов из заданной подсети на наличие открытого порта 9091 и извлечения аутентификационных данных из адресной книги.
- [x]  [GOWITNESS](https://github.com/sensepost/gowitness?tab=readme-ov-file) для проверки IP-адресов из заданной подсети на наличие открытых портов 80, 443, 8000, 8080 и создания скриншотов.
- [ ]  Kerberoasting для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования)
- [ ]  Asreproasting для проведения атаки, запуска брутфорса с заданным словарем и сохранения результата в БД (в процессе тестирования)
## Зависимости
Перед запуском необходимо убедиться в наличии следующих библиотек:
- `psutil`
- `scapy`
- `tabulate`
- `colorama`
- `lxml`

Команда для установки.
```python
pip install psutil scapy tabulate colorama lxml
```
Также необходимо установить дополнительные модули, если они отсутствуют:
```bash
go install github.com/sensepost/gowitness@latest
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
## HELP меню
### seth
```
usage: suzu.py seth [-h] {mitm,show,clear,remove} ...

positional arguments:
  {mitm,show,clear,remove}
                        Доступные команды
    mitm                Запуск SETH на указанную подсеть
    show                Вывод всех паролей
    clear               Очистка базы данных
    remove              Удаление определенного IP-адреса

options:
  -h, --help            show this help message and exit
```
#### mitm
```
usage: suzu.py seth mitm [-h] -i INTERFACE -s SUBNET -r SERVER

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Сетевой интерфейс
  -s SUBNET, --subnet SUBNET
                        Подсеть или одиночный IP для прослушивания
  -r SERVER, --server SERVER
                        RDP сервер
```
#### show
```
usage: suzu.py seth show [-h]

options:
  -h, --help  show this help message and exit
```
#### clear
```
usage: suzu.py seth clear [-h]

options:
  -h, --help  show this help message and exit
```
#### remove
```
usage: suzu.py seth remove [-h] ip

positional arguments:
  ip          IP-адрес для удаления

options:
  -h, --help  show this help message and exit
```
### kyocera
```
usage: suzu.py kyocera [-h] -i INTERFACE -s SUBNET

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Сетевой интерфейс
  -s SUBNET, --subnet SUBNET
                        Подсеть или одиночный IP для сканирования
```
### gowitness
```
usage: suzu.py gowitness [-h] -i INTERFACE -s SUBNET

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Сетевой интерфейс
  -s SUBNET, --subnet SUBNET
                        Подсеть или одиночный IP для сканирования
```
### kerberoasting
```
usage: suzu.py kerberoasting [-h] -u USERNAME -c CREDENTIALS -d DOMAIN [-w WORDLIST] ip

positional arguments:
  ip                    IP-адрес контроллера домена

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Имя пользователя
  -c CREDENTIALS, --credentials CREDENTIALS
                        Пароль или NT-hash
  -d DOMAIN, --domain DOMAIN
                        Домен
  -w WORDLIST, --wordlist WORDLIST
                        Путь к файлу со словарем
```
## Видео-демонстрация запуска скрипта
### seth
https://github.com/SuzumiyaHaruhi1/suzu_seth/assets/84810190/28ed97ee-1053-4d66-8737-72dc51892b7b

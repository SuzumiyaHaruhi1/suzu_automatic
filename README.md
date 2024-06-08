# suzu_SETH
Скрипт предназначен для автоматизации выполнения [SETH](https://github.com/SySS-Research/Seth) для проведения MITM атаки с перехватом аутентификации пользователя на удаленном RDP-сервере. 
В данном скрипте производится сканирование подсети на наличие "живых" IP-адресов, запуск SETH на каждый найденный IP в отдельном потоке, а также работа с базами данных для хранения, изменения и вывода результата в табличном виде.
## Зависимости
Перед запуском необходимо убедиться в наличии следующих библиотек:
- `psutil`
- `scapy`
- `tabulate`
- `colorama`

Команда для установки.
```python
pip install psutil scapy tabulate colorama
```
## Установка
```bash
git clone https://github.com/SuzumiyaHaruhi1/suzu_seth.git
```
```bash
cd suzu_seth
```
```bash
chmod +x seth.sh
```
## Использование
Скрипт поддерживает несколько команд для различных задач. При запуске происходит проверка прав пользователя и если запуск производится не от root, требуется ввести пароль.
### mitm
Предназначен для запуска SETH на указанную подсеть для проведения MITM атаки.
```python
python3 suzu_seth.py mitm -i <interface> -s <subnet> -r <rdp_server>
```
### show
Предназначен для вывода всех имеющихся данных из таблицы `cleartext`, которая хранит в себе перехваченные пароли в чистом виде.
```python
python3 suzu_seth.py show
```
### clear
Предназначен для очистки всех таблиц базы данных.
```python
python3 suzu_seth.py clear
```
### remove
Предназначен для очистки значений (если существуют) для определенного IP-адреса (например, когда был перехвачен только NetNTLMv2 hash и требуется заново запустить SETH на этот IP-адрес).
```python
python3 suzu_seth.py remove <IP-адрес>
```
## HELP меню
### Для модулей в целом
```python
python3 suzu_seth.py -h
```
```
usage: suzu_seth.py [-h] {mitm,show,clear,remove} ...

Automate SETH execution

positional arguments:
  {mitm,show,clear,remove}
                        Available commands
    mitm                Запуск SETH на указанную подсеть
    show                Вывод всех паролей
    clear               Очистка базы данных
    remove              Удаление определенного IP-адреса

options:
  -h, --help            show this help message and exit
```
### mitm
```python
python3 suzu_seth.py mitm -h
```
```
usage: suzu_seth.py mitm [-h] -i INTERFACE -s SUBNET -r SERVER

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Сетевой интерфейс
  -s SUBNET, --subnet SUBNET
                        Подсеть или одиночный IP для прослушивания
  -r SERVER, --server SERVER
                        RDP сервер
```
### show
```python
python3 suzu_seth.py show -h
```
```
usage: suzu_seth.py show [-h]

options:
  -h, --help  show this help message and exit
```
### clear
```python
python3 suzu_seth.py clear -h
```
```
usage: suzu_seth.py clear [-h]

options:
  -h, --help  show this help message and exit
```
### remove
```python
python3 suzu_seth.py remove -h
```
```
usage: suzu_seth.py remove [-h] ip

positional arguments:
  ip          IP-адрес для удаления

options:
  -h, --help  show this help message and exit
```
## Видео-демонстрация запуска скрипта
https://github.com/SuzumiyaHaruhi1/suzu_seth/assets/84810190/28ed97ee-1053-4d66-8737-72dc51892b7b

from flask import Flask, render_template, jsonify, request
import sqlite3

app = Flask(__name__)

# ====================================================================
# База данных
# ====================================================================

def get_tables():
    """
    Получает список всех таблиц в базе данных 'suzu.db', исключая служебную таблицу 'sqlite_sequence'.
    :return: Список названий таблиц.
    """
    with sqlite3.connect('suzu.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        return [table[0] for table in tables if table[0] != 'sqlite_sequence']

def get_table_data(table_name, start_date=None, end_date=None):
    """
    Извлекает данные из указанной таблицы с фильтрацией по дате (если указана).
    :param table_name: Название таблицы.
    :param start_date: Начальная дата для фильтрации данных.
    :param end_date: Конечная дата для фильтрации данных.
    :return: Список столбцов и данных таблицы.
    """
    query = f"SELECT * FROM {table_name}"
    params = []

    if start_date and end_date:
        query += " WHERE date_added BETWEEN ? AND ?"
        params.extend([start_date, end_date])
    elif start_date:
        query += " WHERE date_added >= ?"
        params.append(start_date)
    elif end_date:
        query += " WHERE date_added <= ?"
        params.append(end_date)

    with sqlite3.connect('suzu.db') as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        data = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
    return columns, data

# ====================================================================
# Маршруты приложения Flask
# ====================================================================

@app.route('/')
def index():
    """
    Рендерит главную страницу с перечнем таблиц.
    """
    tables = get_tables()
    return render_template('index.html', tables=tables)

@app.route('/table/<string:table_name>', methods=['GET'])
def table(table_name):
    """
    Возвращает данные указанной таблицы в формате JSON.
    Поддерживает фильтрацию по диапазону дат через параметры запроса.
    :param table_name: Название таблицы.
    :return: JSON с данными таблицы.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    columns, data = get_table_data(table_name, start_date, end_date)
    return jsonify({"columns": columns, "data": data})


# ====================================================================
# Запуск приложения
# ====================================================================

if __name__ == '__main__':
    app.run(debug=True)

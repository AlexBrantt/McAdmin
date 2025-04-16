import hashlib
import os
import secrets
import sqlite3

# Путь к базе данных
DB_PATH = 'users.db'

# Определение ролей пользователей
ROLE_SUPERUSER = 'superuser'
ROLE_ADMIN = 'admin'
ROLE_MODER = 'moder'

# Порядок сортировки ролей (чем меньше значение, тем выше приоритет)
ROLE_PRIORITY = {ROLE_SUPERUSER: 1, ROLE_ADMIN: 2, ROLE_MODER: 3}


def init_db():
    """Инициализация базы данных и создание таблицы пользователей, если она не существует."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Создаем таблицу пользователей, если она не существует
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'moder',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    '''
    )

    # Проверяем, есть ли хотя бы один пользователь в базе
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]

    # Если пользователей нет, создаем суперпользователя по умолчанию
    if user_count == 0:
        default_admin = os.environ.get("ADMIN_USERNAME", "admin")
        default_password = os.environ.get("ADMIN_PASSWORD", "password")

        # Создаем хеш пароля с солью
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256(
            (default_password + salt).encode()
        ).hexdigest()

        # Добавляем суперпользователя в базу
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
            (default_admin, password_hash, salt, ROLE_SUPERUSER),
        )

    conn.commit()
    conn.close()

    # Создаем таблицу логов
    create_logs_table()

    # Создаем суперпользователя, если его нет
    if not get_user('admin'):
        add_user('admin', 'admin', ROLE_SUPERUSER)


def verify_password(username, password):
    """Проверяет правильность пароля для указанного пользователя."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT password_hash, salt FROM users WHERE username = ?', (username,)
    )
    result = cursor.fetchone()

    conn.close()

    if not result:
        return False

    password_hash, salt = result
    expected_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    return password_hash == expected_hash


def get_user(username):
    """Получает информацию о пользователе по имени."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id, username, role FROM users WHERE username = ?',
        (username,),
    )
    user = cursor.fetchone()

    conn.close()

    if not user:
        return None

    return {'id': user[0], 'username': user[1], 'role': user[2]}


def get_all_users():
    """Получает список всех пользователей, отсортированный по ролям и дате создания."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Получаем всех пользователей
    cursor.execute('SELECT id, username, role, created_at FROM users')
    users = cursor.fetchall()

    conn.close()

    # Преобразуем в список словарей
    users_list = [
        {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'created_at': user[3],
            'role_priority': ROLE_PRIORITY.get(
                user[2], 999
            ),  # Добавляем приоритет роли
        }
        for user in users
    ]

    # Сортируем по приоритету роли (возрастание) и дате создания (убывание)
    users_list.sort(key=lambda x: (x['role_priority'], x['created_at']))

    # Удаляем временное поле role_priority
    for user in users_list:
        del user['role_priority']

    return users_list


def add_user(username, password, role=ROLE_MODER):
    """Добавляет нового пользователя в базу данных."""
    # Проверяем, существует ли пользователь с таким именем
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT COUNT(*) FROM users WHERE username = ?', (username,)
    )
    if cursor.fetchone()[0] > 0:
        conn.close()
        return False, "Пользователь с таким именем уже существует"

    # Создаем хеш пароля с солью
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    # Добавляем пользователя в базу
    cursor.execute(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
        (username, password_hash, salt, role),
    )

    conn.commit()
    conn.close()

    return True, "Пользователь успешно добавлен"


def delete_user(user_id):
    """Удаляет пользователя из базы данных."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Проверяем, не пытаемся ли удалить последнего суперпользователя
    cursor.execute(
        'SELECT COUNT(*) FROM users WHERE role = ?', (ROLE_SUPERUSER,)
    )
    superuser_count = cursor.fetchone()[0]

    cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return False, "Пользователь не найден"

    if result[0] == ROLE_SUPERUSER and superuser_count <= 1:
        conn.close()
        return False, "Невозможно удалить последнего суперпользователя"

    # Удаляем пользователя
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

    conn.commit()
    conn.close()

    return True, "Пользователь успешно удален"


def change_password(user_id, new_password):
    """Изменяет пароль пользователя."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь
    cursor.execute('SELECT COUNT(*) FROM users WHERE id = ?', (user_id,))
    if cursor.fetchone()[0] == 0:
        conn.close()
        return False, "Пользователь не найден"

    # Создаем новый хеш пароля с новой солью
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()

    # Обновляем пароль
    cursor.execute(
        'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
        (password_hash, salt, user_id),
    )

    conn.commit()
    conn.close()

    return True, "Пароль успешно изменен"


def change_user_role(user_id, new_role):
    """Изменяет роль пользователя."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь
    cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return False, "Пользователь не найден"

    current_role = result[0]

    # Проверяем, не пытаемся ли изменить роль последнего суперпользователя
    if current_role == ROLE_SUPERUSER and new_role != ROLE_SUPERUSER:
        cursor.execute(
            'SELECT COUNT(*) FROM users WHERE role = ?', (ROLE_SUPERUSER,)
        )
        superuser_count = cursor.fetchone()[0]

        if superuser_count <= 1:
            conn.close()
            return (
                False,
                "Невозможно изменить роль последнего суперпользователя",
            )

    # Обновляем роль
    cursor.execute(
        'UPDATE users SET role = ? WHERE id = ?',
        (new_role, user_id),
    )

    conn.commit()
    conn.close()

    return True, "Роль пользователя успешно изменена"


def change_username(user_id, new_username):
    """Изменяет имя пользователя."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь
    cursor.execute('SELECT COUNT(*) FROM users WHERE id = ?', (user_id,))
    if cursor.fetchone()[0] == 0:
        conn.close()
        return False, "Пользователь не найден"

    # Проверяем, не занято ли новое имя пользователя
    cursor.execute(
        'SELECT COUNT(*) FROM users WHERE username = ? AND id != ?',
        (new_username, user_id),
    )
    if cursor.fetchone()[0] > 0:
        conn.close()
        return False, "Пользователь с таким именем уже существует"

    # Обновляем имя пользователя
    cursor.execute(
        'UPDATE users SET username = ? WHERE id = ?',
        (new_username, user_id),
    )

    conn.commit()
    conn.close()

    return True, "Имя пользователя успешно изменено"


# Создание таблицы логов
def create_logs_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    '''
    )
    conn.commit()
    conn.close()


# Добавление записи в лог
def add_log(user_id, action, details=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
        (user_id, action, details),
    )
    conn.commit()
    conn.close()


# Получение логов конкретного пользователя
def get_user_logs(user_id, limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        '''
    SELECT l.*, u.username 
    FROM logs l
    JOIN users u ON l.user_id = u.id
    WHERE l.user_id = ?
    ORDER BY l.timestamp DESC
    LIMIT ?
    ''',
        (user_id, limit),
    )
    logs = cursor.fetchall()
    conn.close()
    return logs


# Получение всех логов (для общего просмотра)
def get_all_logs(limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        '''
    SELECT l.*, u.username 
    FROM logs l
    JOIN users u ON l.user_id = u.id
    ORDER BY l.timestamp DESC
    LIMIT ?
    ''',
        (limit,),
    )
    logs = cursor.fetchall()
    conn.close()
    return logs


# Инициализируем базу данных при импорте модуля
init_db()

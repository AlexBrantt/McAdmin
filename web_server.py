import os
import re
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from mcrcon import MCRcon

from models import (
    DB_PATH,
    ROLE_ADMIN,
    ROLE_MODER,
    ROLE_SUPERUSER,
    add_log,
    add_role_permission,
    add_user,
    change_password,
    change_user_role,
    change_username,
    check_command_permission,
    create_role_settings_table,
    delete_user,
    get_all_logs,
    get_all_users,
    get_role_permissions,
    get_role_settings,
    get_user,
    get_user_logs,
    remove_role_permission,
    update_role_color,
    verify_password,
)

# Загружаем переменные из файла .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# RCON настройки из .env
RCON_HOST = os.getenv('RCON_HOST')
RCON_PORT = int(os.getenv('RCON_PORT', 17602))
RCON_PASSWORD = os.getenv('RCON_PASSWORD')

# Создаем таблицу настроек ролей при запуске
create_role_settings_table()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'username' not in session:
            return redirect(url_for('login'))

        user = get_user(session['username'])
        if not user or user['role'] != ROLE_SUPERUSER:
            return (
                jsonify(
                    {
                        'error': 'Доступ запрещен. Требуются права суперпользователя.'
                    }
                ),
                403,
            )

        return f(*args, **kwargs)

    return decorated_function


def clean_minecraft_colors(text: str) -> str:
    """Удаляет цветовые коды Minecraft из текста."""
    return re.sub(r'§[0-9a-fk-or]', '', text)


def send_rcon_command(command: str) -> str:
    try:
        with MCRcon(RCON_HOST, RCON_PASSWORD, RCON_PORT) as mcr:
            response = mcr.command(command)
            if not response or response.strip() == "":
                return "Команда успешно выполнена"
            cleaned_response = clean_minecraft_colors(response)
            return cleaned_response
    except Exception as e:
        return f"❌ Ошибка: {str(e)}"


@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            return jsonify({'success': True})
        else:
            return jsonify({'success': False})

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/user_info')
@login_required
def user_info():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    return jsonify(
        {'success': True, 'username': user['username'], 'role': user['role']}
    )


@app.route('/send_command', methods=['POST'])
@login_required
def send_command():
    if 'username' not in session:
        return jsonify({'error': 'Пользователь не авторизован'})

    user = get_user(session['username'])
    if not user:
        return jsonify({'error': 'Пользователь не найден'})

    command = request.form.get('command', '').strip()
    if not command:
        return jsonify({'error': 'Команда не может быть пустой'})

    # Проверяем права на выполнение команды
    if not check_command_permission(user['role'], command):
        return jsonify({'error': 'У вас нет прав для выполнения этой команды'})

    try:
        response = send_rcon_command(command)
        if not response.startswith('❌'):
            response = f"✅ {response}"

        # Логируем действие пользователя
        add_log(user['id'], f"Выполнил команду: {command}", response)

        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)})


# Маршруты для управления пользователями (только для суперпользователей)
@app.route('/users')
@login_required
def users():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user(session['username'])
    if not user:
        return redirect(url_for('login'))

    # Проверяем, имеет ли пользователь права на доступ к странице пользователей
    if user['role'] not in ['superuser', 'admin']:
        return redirect(url_for('index'))

    return render_template('users.html')


@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр списка пользователей
    if user['role'] not in ['superuser', 'admin']:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для просмотра списка пользователей',
            }
        )

    users = get_all_users()
    return jsonify({'success': True, 'users': users})


@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на создание пользователей
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN]:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для создания пользователей',
            }
        )

    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role')

    if not username or not password or not confirm_password or not role:
        return jsonify(
            {
                'success': False,
                'message': 'Все поля обязательны для заполнения',
            }
        )

    if password != confirm_password:
        return jsonify({'success': False, 'message': 'Пароли не совпадают'})

    # Проверяем, может ли пользователь создавать пользователей с указанной ролью
    if user['role'] == 'admin' and role != 'moder':
        return jsonify(
            {
                'success': False,
                'message': 'Администратор может создавать только модераторов',
            }
        )

    if role not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return jsonify({'success': False, 'message': 'Неверная роль'})

    if add_user(username, password, role):
        # Логируем действие пользователя
        add_log(user['id'], f"Создал пользователя: {username} с ролью {role}")
        return jsonify(
            {'success': True, 'message': 'Пользователь успешно создан'}
        )
    else:
        return jsonify(
            {'success': False, 'message': 'Ошибка при создании пользователя'}
        )


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на удаление пользователей
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN]:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для удаления пользователей',
            }
        )

    # Получаем информацию о пользователе, которого пытаемся удалить
    user_to_delete = get_user(user_id)
    if not user_to_delete:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, может ли пользователь удалить указанного пользователя
    if user['role'] == 'admin' and user_to_delete['role'] != 'moder':
        return jsonify(
            {
                'success': False,
                'message': 'Администратор может удалять только модераторов',
            }
        )

    if delete_user(user_id):
        # Логируем действие пользователя
        add_log(
            user['id'], f"Удалил пользователя: {user_to_delete['username']}"
        )
        return jsonify(
            {'success': True, 'message': 'Пользователь успешно удален'}
        )
    else:
        return jsonify(
            {'success': False, 'message': 'Ошибка при удалении пользователя'}
        )


@app.route('/api/users/<int:user_id>/password', methods=['POST'])
@login_required
def update_password(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на изменение паролей
    if user['role'] != ROLE_SUPERUSER and user['id'] != user_id:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для изменения паролей других пользователей',
            }
        )

    new_password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not new_password:
        return jsonify(
            {'success': False, 'message': 'Новый пароль обязателен'}
        )

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Пароли не совпадают'})

    success, message = change_password(user_id, new_password)

    if success:
        # Логируем действие пользователя
        user_to_change = get_user(user_id)
        if user_to_change:
            add_log(
                user['id'],
                f"Изменил пароль пользователя: {user_to_change['username']}",
            )

    return jsonify({'success': success, 'message': message})


@app.route('/api/users/<int:user_id>/role', methods=['POST'])
@login_required
def change_user_role(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на изменение ролей
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN]:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для изменения ролей пользователей',
            }
        )

    role = request.form.get('role')
    if not role:
        return jsonify({'success': False, 'message': 'Роль не указана'})

    # Получаем информацию о пользователе, роль которого пытаемся изменить
    user_to_change = get_user(user_id)
    if not user_to_change:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, может ли пользователь изменить роль указанного пользователя
    if user['role'] == 'admin' and role != 'moder':
        return jsonify(
            {
                'success': False,
                'message': 'Администратор может назначать только роль модератора',
            }
        )

    if role not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return jsonify({'success': False, 'message': 'Неверная роль'})

    if change_user_role(user_id, role):
        # Логируем действие пользователя
        add_log(
            user['id'],
            f"Изменил роль пользователя {user_to_change['username']} на {role}",
        )
        return jsonify(
            {'success': True, 'message': 'Роль пользователя успешно изменена'}
        )
    else:
        return jsonify(
            {
                'success': False,
                'message': 'Ошибка при изменении роли пользователя',
            }
        )


@app.route('/api/users/<int:user_id>/username', methods=['POST'])
@login_required
def update_username(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на изменение имен пользователей
    if user['role'] != ROLE_SUPERUSER and user['id'] != user_id:
        return jsonify(
            {
                'success': False,
                'message': 'У вас нет прав для изменения имен других пользователей',
            }
        )

    new_username = request.form.get('username', '')

    if not new_username:
        return jsonify(
            {'success': False, 'message': 'Новое имя пользователя обязательно'}
        )

    # Получаем информацию о пользователе, имя которого пытаемся изменить
    user_to_change = get_user(user_id)
    if not user_to_change:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    success, message = change_username(user_id, new_username)

    if success:
        # Логируем действие пользователя
        add_log(
            user['id'],
            f"Изменил имя пользователя {user_to_change['username']} на {new_username}",
        )

    return jsonify({'success': success, 'message': message})


# Маршруты для работы с логами
@app.route('/logs')
@login_required
def logs():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user(session['username'])
    if not user:
        return redirect(url_for('login'))

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return redirect(url_for('index'))

    return render_template('logs.html')


@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return jsonify(
            {'success': False, 'message': 'У вас нет прав для просмотра логов'}
        )

    try:
        logs = get_all_logs()
        logs_list = []
        for log in logs:
            log_dict = {
                'id': log['id'],
                'timestamp': (
                    str(log['timestamp']) if log['timestamp'] else None
                ),
                'action': log['action'],
                'details': log['details'],
                'username': log['username'],
                'role': log['role'],
            }
            logs_list.append(log_dict)
        return jsonify({'success': True, 'logs': logs_list})
    except Exception as e:
        app.logger.error(f"Error getting logs: {str(e)}")
        return jsonify(
            {
                'success': False,
                'message': f'Ошибка при получении логов: {str(e)}',
            }
        )


@app.route('/api/logs/user/<int:user_id>', methods=['GET'])
@login_required
def get_user_logs_api(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return jsonify(
            {'success': False, 'message': 'У вас нет прав для просмотра логов'}
        )

    logs = get_user_logs(user_id)
    return jsonify({'success': True, 'logs': logs})


@app.route('/logs/user/<int:user_id>')
@login_required
def user_logs(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user(session['username'])
    if not user:
        return redirect(url_for('login'))

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN]:
        return redirect(url_for('index'))

    return render_template('user_logs.html')


@app.route('/api/users/<int:user_id>/logs')
@login_required
def get_user_logs_api_v2(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in ['superuser', 'admin']:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    try:
        logs = get_user_logs(user_id)
        # Преобразуем объекты Row в словари
        logs_dict = []
        for log in logs:
            # Проверяем тип timestamp и форматируем соответственно
            timestamp = log['timestamp']
            if isinstance(timestamp, str):
                formatted_timestamp = timestamp
            else:
                formatted_timestamp = (
                    timestamp.isoformat() if timestamp else None
                )

            log_dict = {
                'id': log['id'],
                'user_id': log['user_id'],
                'action': log['action'],
                'details': log['details'],
                'timestamp': formatted_timestamp,
            }
            logs_dict.append(log_dict)
        return jsonify({'success': True, 'logs': logs_dict})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/users/<int:user_id>')
@login_required
def get_user_info(user_id):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    current_user = get_user(session['username'])
    if not current_user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр информации о других пользователях
    if current_user['role'] not in ['superuser', 'admin']:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, username, role, created_at FROM users WHERE id = ?',
            (user_id,),
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify(
                {'success': False, 'message': 'Пользователь не найден'}
            )

        user_info = {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'created_at': user[3],
        }

        return jsonify({'success': True, 'user': user_info})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/logs')
@login_required
def get_all_logs_api():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Проверяем, имеет ли пользователь права на просмотр логов
    if user['role'] not in [ROLE_SUPERUSER, ROLE_ADMIN, ROLE_MODER]:
        return jsonify(
            {'success': False, 'message': 'У вас нет прав для просмотра логов'}
        )

    try:
        logs = (
            get_all_logs()
        )  # Используем импортированную функцию из models.py

        # Преобразуем результаты в список словарей
        logs_list = []
        for log in logs:
            # Преобразуем объект Row в словарь
            log_dict = dict(log)

            # Форматируем timestamp если он есть
            if log_dict['timestamp']:
                try:
                    if isinstance(log_dict['timestamp'], str):
                        log_dict['timestamp'] = log_dict['timestamp']
                    else:
                        log_dict['timestamp'] = str(log_dict['timestamp'])
                except (AttributeError, ValueError):
                    log_dict['timestamp'] = str(log_dict['timestamp'])

            logs_list.append(log_dict)

        return jsonify({'success': True, 'logs': logs_list})
    except Exception as e:
        app.logger.error(f"Error getting logs: {str(e)}")
        return jsonify(
            {
                'success': False,
                'message': f'Ошибка при получении логов: {str(e)}',
            }
        )


@app.route('/settings')
@login_required
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return redirect(url_for('index'))

    return render_template('settings.html')


@app.route('/api/roles/settings', methods=['GET'])
@login_required
def get_roles_settings():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    try:
        settings = get_role_settings()
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/roles/permissions', methods=['GET'])
@login_required
def get_roles_permissions():
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    try:
        permissions = get_role_permissions()
        return jsonify({'success': True, 'permissions': permissions})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/roles/<role>/color', methods=['POST'])
@login_required
def update_role_color_api(role):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    data = request.get_json()
    if not data or 'color' not in data:
        return jsonify({'success': False, 'message': 'Цвет не указан'})

    success, message = update_role_color(role, data['color'])
    return jsonify({'success': success, 'message': message})


@app.route('/api/roles/<role>/permissions', methods=['POST'])
@login_required
def add_role_permission_api(role):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    data = request.get_json()
    if not data or 'command_pattern' not in data:
        return jsonify(
            {'success': False, 'message': 'Шаблон команды не указан'}
        )

    success, message = add_role_permission(role, data['command_pattern'])
    return jsonify({'success': success, 'message': message})


@app.route(
    '/api/roles/<role>/permissions/<command_pattern>', methods=['DELETE']
)
@login_required
def remove_role_permission_api(role, command_pattern):
    if 'username' not in session:
        return jsonify(
            {'success': False, 'message': 'Пользователь не авторизован'}
        )

    user = get_user(session['username'])
    if not user or user['role'] != ROLE_SUPERUSER:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})

    success, message = remove_role_permission(role, command_pattern)
    return jsonify({'success': success, 'message': message})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

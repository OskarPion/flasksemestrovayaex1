import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
import requests
import config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.github import make_github_blueprint, github
from flask_mail import Mail, Message
from flask_migrate import Migrate
from oauthlib.oauth2 import WebApplicationClient
from requests_oauthlib import OAuth2Session
import secrets
from itsdangerous import URLSafeTimedSerializer as Serializer
from extensions import db, mail, migrate, login_manager
from models import User, Flight, Booking, Payment, Review


# Flask configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# Конфигурация приложения
app.config['SECRET_KEY'] = 's3cr3t_k3y_for_my_flask_app_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/semestrflask1bd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Конфигурация соли для безопасности
app.config['SECURITY_PASSWORD_SALT'] = 'my_super_secret_salt'

# Настройки для почты
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'dmitriy.gavrilov.1975@internet.ru'
app.config['MAIL_PASSWORD'] = 'J091TdwKPSNadvwmtprG'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Инициализация расширений
db.init_app(app)
mail.init_app(app)
migrate.init_app(app, db)

# Инициализация Flask-Login
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Валидация пароля
def validate_password(password):
    if len(password) < 6:
        return False
    return True


# Функция для генерации токена
def get_reset_token(user, expires_in=1800):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps({'user_id': user.id}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

# Функция для проверки токена
def verify_reset_token(token, expires_in=1800):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expires_in)['user_id']
    except Exception as e:
        print(f"Error verifying token: {e}")  # Логирование ошибки для отладки
        return None
    return User.query.get(user_id)

# GitHub OAuth
github_blueprint = make_github_blueprint(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_to="github_callback"
)
app.register_blueprint(github_blueprint, url_prefix="/github")


@app.route('/github/callback')
def github_callback():
    print("GitHub callback route hit!")  # Отладочное сообщение

    if not github.authorized:
        print("Not authorized, redirecting to login")
        return redirect(url_for('login'))

    account_info = github.get('/user')
    print(f"Account info: {account_info}")

    if account_info.ok:
        account_data = account_info.json()
        email = account_data.get('email')
        username = account_data.get('login')
        print(f"GitHub user email: {email}, username: {username}")

        user = User.query.filter_by(email=email).first()

        if user is None:
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        return redirect(url_for('home'))
    else:
        flash('Ошибка авторизации через GitHub.', 'danger')
        return redirect(url_for('login'))


YANDEX_CLIENT_ID = config.YANDEX_CLIENT_ID
YANDEX_CLIENT_SECRET = config.YANDEX_CLIENT_SECRET
YANDEX_AUTHORIZATION_BASE_URL = "https://oauth.yandex.ru/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.ru/token"
YANDEX_USER_INFO_URL = "https://login.yandex.ru/info"

yandex_client = WebApplicationClient(YANDEX_CLIENT_ID)
yandex = OAuth2Session(YANDEX_CLIENT_ID, redirect_uri="http://127.0.0.1:5000/yandex/callback")


@app.route('/login/yandex')
def yandex_login():
    # URL для запроса авторизации
    request_uri = yandex_client.prepare_request_uri(
        YANDEX_AUTHORIZATION_BASE_URL,
        redirect_uri="http://127.0.0.1:5000/yandex/callback",  # URL для редиректа после успешной авторизации
        scope=["login:email"]
    )
    return redirect(request_uri)


@app.route('/yandex/callback')
def yandex_callback():
    # Получаем токен после авторизации
    token = yandex.fetch_token(
        YANDEX_TOKEN_URL,
        client_secret=YANDEX_CLIENT_SECRET,
        authorization_response=request.url
    )

    # Используем токен для получения информации о пользователе
    resp = yandex.get(YANDEX_USER_INFO_URL)

    if resp.ok:
        account_info = resp.json()
        email = account_info.get('default_email', None)  # Получаем email пользователя
        username = account_info.get('login', 'NoUsername')  # Получаем логин пользователя

        if email is None:
            flash('Не удалось получить email от Яндекс.', 'danger')
            return redirect(url_for('login'))

        # Проверяем, существует ли пользователь
        user = User.query.filter_by(email=email).first()
        if user is None:
            # Если пользователя нет, создаем нового
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()

        # Входим в систему
        login_user(user)

        # Перенаправляем на профиль
        return redirect(url_for('profile'))
    else:
        flash('Ошибка при авторизации через Яндекс.', 'danger')
        return redirect(url_for('login'))


@app.route('/flights/add', methods=['GET', 'POST'])
@login_required
def add_flight():
    if request.method == 'POST':
        flight_number = request.form['flight_number']
        departure = request.form['departure']
        arrival = request.form['arrival']
        price = request.form['price']

        new_flight = Flight(
            flight_number=flight_number,
            departure=departure,
            arrival=arrival,
            price=price
        )

        db.session.add(new_flight)
        db.session.commit()
        flash('Рейс успешно добавлен!', 'success')
        return redirect(url_for('view_flights'))

    return render_template('add_flight.html')


@app.route('/flights', methods=['GET'])
@login_required
def view_flights():
    flights = Flight.query.all()
    return render_template('view_flights.html', flights=flights)


@app.route('/flights/edit/<int:flight_id>', methods=['GET', 'POST'])
@login_required
def edit_flight(flight_id):
    flight = Flight.query.get_or_404(flight_id)

    if request.method == 'POST':
        flight.flight_number = request.form['flight_number']
        flight.departure = request.form['departure']
        flight.arrival = request.form['arrival']
        flight.price = request.form['price']

        db.session.commit()
        flash('Рейс успешно обновлен!', 'success')
        return redirect(url_for('view_flights'))

    return render_template('edit_flight.html', flight=flight)


@app.route('/flights/delete/<int:flight_id>', methods=['POST'])
@login_required
def delete_flight(flight_id):
    flight = Flight.query.get_or_404(flight_id)
    db.session.delete(flight)
    db.session.commit()
    flash('Рейс успешно удален!', 'info')
    return redirect(url_for('view_flights'))


# Главная страница
@app.route('/')
def home():
    return render_template('search.html')


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if '@' not in email:
            flash('Неверный формат email.', 'danger')
            return redirect(url_for('register'))
        if not validate_password(password):
            flash('Пароль должен быть длиной не менее 6 символов.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


# Вход в систему
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Успешный вход в систему!', 'success')
            return redirect(url_for('home'))
        flash('Неправильные учетные данные. Попробуйте снова.', 'danger')
    return render_template('login.html')


# Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('home'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', current_user=current_user)



# Страница контактов
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        message = request.form['message']
        flash('Сообщение отправлено!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')


# Запрос на восстановление пароля
@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('На ваш email отправлено письмо с инструкциями для восстановления пароля.', 'info')
            return redirect(url_for('login'))
        flash('Пользователь с таким email не найден.', 'danger')
    return render_template('reset_request.html')


# Восстановление пароля
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = verify_reset_token(token)
    if not user:
        flash('Неверный или истекший токен.', 'danger')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Пароли не совпадают. Попробуйте снова.', 'danger')
            return redirect(url_for('reset_password', token=token))
        if not validate_password(password):
            flash('Пароль должен быть длиной не менее 6 символов.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user.set_password(password)
        db.session.commit()
        flash('Пароль успешно изменен. Вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


def send_reset_email(user):
    token = get_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)

    # Убедитесь, что тело письма корректно формируется
    msg = Message('Восстановление пароля', sender='dmitriy.gavrilov.1975@internet.ru', recipients=[user.email])
    msg.body = f'''Чтобы восстановить пароль, перейдите по следующей ссылке:
{reset_url}
'''

    try:
        mail.send(msg)
    except Exception as e:
        print(f"Ошибка отправки email: {e}")  # Для отладки


city_to_iata = {
    'Москва': 'MOW',
    'Казань': 'KZN',
    'Санкт-Петербург': 'LED',
    'Лондон': 'LHR',
    'Париж': 'CDG',
    'Нью-Йорк': 'JFK',
    'Токио': 'HND'
}


@app.route('/search', methods=['POST'])
@login_required
def search():
    from_city_name = request.form['from']
    to_city_name = request.form['to']
    departure_date = request.form['departure']
    return_date = request.form['return']
    passengers = request.form['passengers']

    # Convert city names to IATA codes
    from_city = city_to_iata.get(from_city_name, None)
    to_city = city_to_iata.get(to_city_name, None)

    if not from_city or not to_city:
        flash("Некорректные города. Пожалуйста, проверьте правильность ввода.", 'danger')
        return redirect(url_for('home'))

    params = {
        'origin': from_city,
        'destination': to_city,
        'depart_date': departure_date,
        'return_date': return_date,
        'currency': config.CURRENCY,
        'token': config.API_KEY,
        'limit': 5
    }


    response = requests.get(config.BASE_URL, params=params)
    data = response.json()

    if response.status_code == 200 and 'data' in data:
        flights = data['data']
        for flight in flights:
            print(flight)
    else:
        flights = []

    return render_template('results.html', flights=flights, from_city=from_city_name, to_city=to_city_name,
                           departure_date=departure_date, return_date=return_date,
                           passengers=passengers)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
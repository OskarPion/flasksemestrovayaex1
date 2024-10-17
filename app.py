from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests
import os
import config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_migrate import Migrate
import secrets
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_dance.contrib.github import make_github_blueprint, github
from oauthlib.oauth2 import WebApplicationClient
from requests_oauthlib import OAuth2Session

app = Flask(__name__)

# Конфигурация приложения
app.config['SECRET_KEY'] = 's3cr3t_k3y_for_my_flask_app_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/semestrflask1bd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройки для почты
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'dmitriy.gavrilov.1975@internet.ru'
app.config['MAIL_PASSWORD'] = 'J091TdwKPSNadvwmtprG'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Инициализация базы данных и почты
db = SQLAlchemy(app)
mail = Mail(app)

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Валидация пароля
def validate_password(password):
    if len(password) < 6:
        return False
    return True


# Функция для генерации токена
def get_reset_token(user, expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'], expires_sec)
    return s.dumps({'user_id': user.id}).decode('utf-8')


# Функция для проверки токена
def verify_reset_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        return None
    return User.query.get(user_id)


# GitHub OAuth
github_blueprint = make_github_blueprint(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_to="github_login"
)
app.register_blueprint(github_blueprint, url_prefix="/github")




YANDEX_CLIENT_ID = config.YANDEX_CLIENT_ID
YANDEX_CLIENT_SECRET = config.YANDEX_CLIENT_SECRET
YANDEX_AUTHORIZATION_BASE_URL = "https://oauth.yandex.ru/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.ru/token"
YANDEX_USER_INFO_URL = "https://login.yandex.ru/info"

yandex_client = WebApplicationClient(YANDEX_CLIENT_ID)

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
    # Получаем авторизационный код из запроса
    code = request.args.get('code')

    # Подготавливаем запрос на получение токена
    token_url, headers, body = yandex_client.prepare_token_request(
        YANDEX_TOKEN_URL,
        authorization_response=request.url,
        redirect_url="http://127.0.0.1:5000/yandex/callback",
        code=code
    )

    # Выполняем запрос на получение токена
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET)
    )

    # Парсим токен
    yandex_client.parse_request_body_response(token_response.text)

    # Запрашиваем информацию о пользователе
    uri, headers, body = yandex_client.add_token(YANDEX_USER_INFO_URL)
    user_info_response = requests.get(uri, headers=headers, data=body)

    # Получаем информацию о пользователе
    user_info = user_info_response.json()
    session['email'] = user_info.get('default_email')

    return redirect(url_for('profile'))



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
def profile():
    if 'email' in session:
        return f"Logged in as: {session['email']}"
    return redirect(url_for('login'))


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


# Функция для отправки письма с восстановлением пароля
def send_reset_email(user):
    token = get_reset_token(user)
    msg = Message('Восстановление пароля', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''Чтобы восстановить пароль, перейдите по следующей ссылке:
{url_for('reset_password', token=token, _external=True)}
'''
    mail.send(msg)


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
        db.create_all()  # Создаем таблицы
    app.run(debug=True)
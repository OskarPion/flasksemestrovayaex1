from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_migrate import Migrate
import secrets

app = Flask(__name__)



# Конфигурация приложения
app.config['SECRET_KEY'] = 's3cr3t_k3y_for_my_flask_app_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/semestrflask1bd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройки для почты
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'dmitriy.gavrilov.1975@internet.ru'  # Ваша почта
app.config['MAIL_PASSWORD'] = 'J091TdwKPSNadvwmtprG'  # Ваш пароль от почты
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True  # Mail.ru использует SSL на порте 465


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

        # Проверка валидности email и пароля
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
    user = User.query.filter_by(reset_token=token).first()
    if user is None:
        flash('Неверный или истекший токен.', 'danger')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        password = request.form['password']
        if not validate_password(password):
            flash('Пароль должен быть длиной не менее 6 символов.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user.set_password(password)
        user.reset_token = None
        db.session.commit()
        flash('Ваш пароль успешно обновлен. Теперь вы можете войти в систему.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Функция отправки письма с токеном восстановления пароля
def send_reset_email(user):
    token = secrets.token_hex(16)
    user.reset_token = token
    db.session.commit()

    msg = Message('Восстановление пароля', sender='dmitriy.gavrilov.1975@internet.ru', recipients=[user.email])
    msg.body = f'''Для восстановления пароля перейдите по следующей ссылке:
{url_for('reset_password', token=token, _external=True)}

Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.
'''
    mail.send(msg)

# Поиск рейсов
@app.route('/search', methods=['POST'])
@login_required
def search():
    from_city_name = request.form['from']
    to_city_name = request.form['to']
    departure_date = request.form['departure']
    return_date = request.form['return']
    passengers = request.form['passengers']

    # Преобразование названий городов в IATA-коды
    from_city = city_to_iata.get(from_city_name, None)
    to_city = city_to_iata.get(to_city_name, None)

    if not from_city or not to_city:
        return "Некорректные города. Пожалуйста, проверьте правильность ввода."

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
            print(flight)  # Выводим весь объект рейса для проверки
    else:
        flights = []

    return render_template('results.html', flights=flights, from_city=from_city_name, to_city=to_city_name,
                           departure_date=departure_date, return_date=return_date,
                           passengers=passengers)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создаем таблицы
    app.run(debug=True)

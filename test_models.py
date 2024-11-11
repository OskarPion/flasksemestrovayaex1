import pytest
from datetime import datetime
from app import app, db  # импортируем app напрямую
from models import User, Flight

@pytest.fixture
def test_app():
    
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"  # SQLite база данных в памяти
    })
    with app.app_context():
        db.create_all()
        yield app  # отдаём контекст приложения для тестов
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(test_app):
    return test_app.test_client()

@pytest.fixture
def init_database(app):
    with app.app_context():
        # Создаем начальные данные для тестов, если необходимо
        user = User(username="testuser", email="testuser@example.com")
        user.set_password("testpassword")
        db.session.add(user)
        db.session.commit()

        flight = Flight(
            flight_number="AB123",
            airline="Test Airline",
            departure_city="Moscow",
            arrival_city="New York",
            departure_time=datetime(2024, 12, 1, 10, 0),  # Используем datetime вместо строки
            arrival_time=datetime(2024, 12, 1, 18, 0),    # Используем datetime вместо строки
            price=500
        )
        db.session.add(flight)
        db.session.commit()

        yield db
        db.session.remove()

# Тесты для модели User
def test_create_user(init_database):
    user = User.query.filter_by(username="testuser").first()
    assert user is not None
    assert user.email == "testuser@example.com"
    assert user.check_password("testpassword") is True

def test_user_password_hashing(init_database):
    user = User.query.filter_by(username="testuser").first()
    assert user.check_password("wrongpassword") is False
    assert user.check_password("testpassword") is True

# Тесты для модели Flight
def test_create_flight(init_database):
    flight = Flight.query.filter_by(flight_number="AB123").first()
    assert flight is not None
    assert flight.airline == "Test Airline"
    assert flight.departure_city == "Moscow"
    assert flight.arrival_city == "New York"
    assert flight.price == 500

def test_update_flight(init_database):
    flight = Flight.query.filter_by(flight_number="AB123").first()
    flight.price = 600
    db.session.commit()
    updated_flight = Flight.query.filter_by(flight_number="AB123").first()
    assert updated_flight.price == 600

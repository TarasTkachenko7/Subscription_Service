from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=False) 
    last_activity = db.Column(db.DateTime) 
    registration_date = db.Column(db.DateTime, default=datetime.now)
    subscription = db.Column(db.String(20), server_default='Базовая', nullable=False)
    balance = db.Column(db.Integer, default=0, nullable=False)
    next_payment_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.login}>'

migrate = Migrate(app, db)

@app.route('/', methods=['POST', 'GET'])
def my():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        action = request.form.get('action')

        if not login or not password:
            flash('Заполните все поля', 'error')
            return redirect(url_for('my'))

        # 1. Логика ВХОДА
        if action == 'login':
            user = Users.query.filter_by(login=login).first()

            if not user:
                flash('Пользователь не найден. Зарегистрируйтесь', 'error')
            elif not check_password_hash(user.password, password):
                flash('Неверный пароль', 'error')
            else:
                user.is_active = True
                user.last_activity = datetime.now().replace(microsecond=0)
                db.session.commit()
                session['user_id'] = user.id  # Сохраняем в сессию
                flash('Вход выполнен успешно!', 'success')
                return redirect(url_for('head'))

        # 2. Логика РЕГИСТРАЦИИ
        elif action == 'register':
            if Users.query.filter_by(login=login).first():
                flash('Пользователь с таким логином уже существует', 'error')
            else:
                hashed_pw = generate_password_hash(password)
                new_user = Users(login=login, password=hashed_pw, subscription='Базовая')
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Ошибка регистрации: {str(e)}', 'error')

        # 3. Логика ВОССТАНОВЛЕНИЯ ПАРОЛЯ
        elif action == 'forgot':
            user = Users.query.filter_by(login=login).first()
            if user:
                new_password = secrets.token_urlsafe(8)
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash(f'Ваш новый пароль: {new_password}', 'info')
            else:
                flash('Пользователь не найден', 'error')

    return render_template("my.html")


@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        user = Users.query.get(session['user_id'])
        if user:
            user.is_active = False
            user.last_activity = datetime.now().replace(microsecond=0)
            db.session.commit()
        session.pop('user_id', None)
    flash('Вы успешно вышли', 'success')
    return redirect(url_for('my'))


@app.before_request
def check_session():
    if request.endpoint in ('my', 'static'):
        return

    if 'user_id' in session:
        user = Users.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Ваша сессия истекла', 'warning')
            return redirect(url_for('my'))

        session_inactive = (user.last_activity is None or
                            user.last_activity < datetime.now().replace(microsecond=0) - timedelta(minutes=180))

        if session_inactive:
            user.is_active = False
            db.session.commit()

            session.clear()
            flash('Ваша сессия истекла из-за неактивности', 'warning')
            return redirect(url_for('my'))


@app.route('/spisok')
def spisok():
    autorizations = Users.query.order_by(Users.id).all()
    return render_template("spisok.html", data=autorizations)


@app.route('/menu')
def menu():
    return render_template("menu.html")


@app.route('/head')
def head():
    return render_template("head.html")


@app.route('/balance')
def balance():
    return render_template("balance.html")


@app.route('/profile')
def profile():
    user = Users.query.get(session['user_id'])
    return render_template("profile.html", user=user)


@app.route('/subscribe')
def subscribe():
    user = Users.query.get(session['user_id'])
    return render_template("subscribe.html", user=user)


if __name__ == "__main__":
    app.run(debug=True)

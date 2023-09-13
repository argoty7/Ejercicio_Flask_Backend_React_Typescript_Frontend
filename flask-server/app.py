from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

from database import db
#from models import User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '0000'

db.init_app(app)

migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(userid):
    return User.query.get(userid)


# Rutas
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']

    # Comprobar si el usuario ya existe
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'message': 'El nombre de usuario ya está en uso'}), 400

    # Crear un nuevo usuario
    new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Registro exitoso'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Nombre de usuario o contraseña incorrectos'}), 401

    login_user(user)
    return jsonify({'message': 'Inicio de sesión exitoso'})

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    return jsonify({'username': current_user.username, 'email': current_user.email})

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Cierre de sesión exitoso'})

if __name__ == '__main__':
    app.run(debug=True)

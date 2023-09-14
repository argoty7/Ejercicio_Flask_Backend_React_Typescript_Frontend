# Autor: Camilo Enrique Argoty Pulido
# Fecha: 2023-09-14
# Descripción: Servidor de Flask para servir de Backend a una aplicación de React

# Importar librerías
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

# Importar la base de datos
from database import db

# Configuración de la base de datos. Se utiliza SQLite para facilitar la configuración
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '0000'

# Inicio de la base de datos 
db.init_app(app)

# Definición de las migraciones
migrate = Migrate(app, db)

# Definicion del login_manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Decorador para cargar el usuario
@login_manager.user_loader
def load_user(userid):
    return User.query.get(userid)


# Rutas
# Ruta de página de registro e inicio
@app.route('/register', methods=['POST'])
def register():
    # Obtener los datos del formulario
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
    
    # Retornar un mensaje de éxito
    return jsonify({'message': 'Registro exitoso'})

# Ruta de inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    # Obtener los datos del formulario
    data = request.json
    username = data['username']
    password = data['password']

    # Comprobar si el usuario existe
    user = User.query.filter_by(username=username).first()

    # Comprobar si la contraseña es correcta
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Nombre de usuario o contraseña incorrectos'}), 401

    # Iniciar sesión
    login_user(user)
    return jsonify({'message': 'Inicio de sesión exitoso'})

# Ruta de perfil
@app.route('/profile', methods=['GET'])
# Decorador para requerir inicio de sesión
@login_required
def profile():
    # Retornar los datos del usuario
    return jsonify({'username': current_user.username, 'email': current_user.email})


# Ruta de cierre de sesión
@app.route('/logout', methods=['GET'])
# Decorador para requerir inicio de sesión
@login_required
def logout():
    # Cerrar sesión
    logout_user()

    # Retornar un mensaje de éxito
    return jsonify({'message': 'Cierre de sesión exitoso'})

# Inicio del servidor
if __name__ == '__main__':
    # Ejecución del servidor, incluyendo el modo de depuración y el puerto
    app.run(debug=True, host='0.0.0.0',port=5000)

import os
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
import bcrypt
import jwt
from datetime import datetime, timedelta
import yagmail
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET')

# Configurar la conexión a la base de datos
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f'Error al conectar con la base de datos: {e}')
        return None

# Ruta para registrar al usuario
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')

    # Hash de la contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    connection = get_db_connection()
    if not connection:
        return jsonify({'message': 'Error al conectar con la base de datos'}), 500

    cursor = connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO user (username, email, password, user_type, email_verified) VALUES (%s, %s, %s, %s, %s)",
            (username, email, hashed_password, user_type, False)
        )
        connection.commit()

        # Generar token de verificación
        token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')

        # Configurar y enviar correo de verificación
        verification_url = f"https://proyecto-bs4m.onrender.com/verify?token={token}"  
        yag = yagmail.SMTP(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))
        yag.send(
            to=email,
            subject="Verifica tu correo electrónico",
            contents=f"Haz clic en el siguiente enlace para verificar tu correo: {verification_url}"
        )

        return jsonify({'message': 'Usuario registrado, verifica tu correo electrónico'})
    except Error as e:
        print(f'Error al registrar usuario: {e}')
        return jsonify({'message': f'Error al registrar usuario: {str(e)}'}), 500
    finally:
        cursor.close()
        connection.close()

# Ruta para verificar el correo
@app.route('/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token')

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']

        connection = get_db_connection()
        if not connection:
            return jsonify({'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()
        cursor.execute("UPDATE user SET email_verified = TRUE WHERE email = %s", (email,))
        connection.commit()

        return jsonify({'message': 'Correo verificado exitosamente'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Enlace de verificación expirado'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Enlace de verificación inválido'}), 400
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    connection = get_db_connection()
    if not connection:
        return jsonify({'message': 'Error al conectar con la base de datos'}), 500

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # Verificar la contraseña
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Verificar si el correo fue confirmado
                if not user['email_verified']:
                    return jsonify({'message': 'Debes verificar tu correo antes de iniciar sesión'}), 403
                return jsonify({'message': 'Inicio de sesión exitoso'})
            else:
                return jsonify({'message': 'Contraseña incorrecta'}), 401
        else:
            return jsonify({'message': 'Usuario no encontrado'}), 401
    finally:
        cursor.close()
        connection.close()

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

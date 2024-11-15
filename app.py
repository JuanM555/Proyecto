import os
import logging
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

# Configurar el log para depuración
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
            logging.info("Conexión a la base de datos establecida.")
            return connection
    except Error as e:
        logging.error(f'Error al conectar con la base de datos: {e}')
        return None

# Ruta para registrar al usuario
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    logging.debug(f"Datos recibidos para registro: {data}")

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')

    if not username or not email or not password or not user_type:
        logging.warning("Faltan datos en la solicitud de registro.")
        return jsonify({'message': 'Todos los campos son obligatorios'}), 400

    # Hash de la contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    logging.info("Contraseña hasheada correctamente.")

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
        logging.info(f"Usuario {username} registrado en la base de datos.")

        # Generar token de verificación
        token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
        logging.info(f"Token generado para {email}: {token}")

        # Configurar y enviar correo de verificación
        verification_url = f"https://proyecto-bs4m.onrender.com/verify?token={token}"
        try:
            yag = yagmail.SMTP(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))
            yag.send(
                to=email,
                subject="Verifica tu correo electrónico",
                contents=f"Haz clic en el siguiente enlace para verificar tu correo: {verification_url}"
            )
            logging.info(f"Correo de verificación enviado a {email}.")
        except Exception as email_error:
            logging.error(f"Error al enviar el correo: {email_error}")
            return jsonify({'message': 'Error al enviar el correo de verificación'}), 500

        return jsonify({'message': 'Usuario registrado, verifica tu correo electrónico'})
    except Error as db_error:
        logging.error(f'Error al registrar usuario en la base de datos: {db_error}')
        return jsonify({'message': f'Error al registrar usuario: {str(db_error)}'}), 500
    finally:
        cursor.close()
        connection.close()

# Ruta para verificar el correo
@app.route('/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    logging.debug(f"Token recibido para verificación: {token}")

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']
        logging.info(f"Token decodificado correctamente. Email: {email}")

        connection = get_db_connection()
        if not connection:
            return jsonify({'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()
        cursor.execute("UPDATE user SET email_verified = TRUE WHERE email = %s", (email,))
        connection.commit()
        logging.info(f"Correo {email} verificado en la base de datos.")

        return jsonify({'message': 'Correo verificado exitosamente'})
    except jwt.ExpiredSignatureError:
        logging.warning("El token ha expirado.")
        return jsonify({'message': 'Enlace de verificación expirado'}), 400
    except jwt.InvalidTokenError:
        logging.error("El token es inválido.")
        return jsonify({'message': 'Enlace de verificación inválido'}), 400
    except Exception as e:
        logging.error(f"Error desconocido en la verificación de correo: {e}")
        return jsonify({'message': 'Error al verificar el correo'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    logging.debug(f"Datos recibidos para inicio de sesión: {data}")

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
            logging.info(f"Usuario encontrado: {email}")
            # Verificar la contraseña
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                logging.info("Contraseña verificada correctamente.")
                # Verificar si el correo fue confirmado
                if not user['email_verified']:
                    logging.warning(f"Usuario {email} no ha verificado su correo.")
                    return jsonify({'message': 'Debes verificar tu correo antes de iniciar sesión'}), 403
                return jsonify({'message': 'Inicio de sesión exitoso'})
            else:
                logging.warning("Contraseña incorrecta.")
                return jsonify({'message': 'Contraseña incorrecta'}), 401
        else:
            logging.warning("Usuario no encontrado.")
            return jsonify({'message': 'Usuario no encontrado'}), 401
    except Exception as e:
        logging.error(f"Error durante el inicio de sesión: {e}")
        return jsonify({'message': 'Error durante el inicio de sesión'}), 500
    finally:
        cursor.close()
        connection.close()

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

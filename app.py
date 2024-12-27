import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS 
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

# Configurar CORS
CORS(app, resources={r"/*": {"origins": "*"}})  # Permitir todas las solicitudes

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
        logging.error(f"[DB001] Error al conectar con la base de datos: {e}")
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
        logging.warning("[REG001] Faltan datos en la solicitud de registro.")
        return jsonify({'code': 'REG001', 'message': 'Todos los campos son obligatorios'}), 400

    # Hash de la contraseña
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logging.info("Contraseña hasheada correctamente.")
    except Exception as e:
        logging.error(f"[REG002] Error al hashear la contraseña: {e}")
        return jsonify({'code': 'REG002', 'message': 'Error al procesar la contraseña'}), 500

    connection = get_db_connection()
    if not connection:
        return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

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
                subject="¡Bienvenido a SkillSwap! Completa tu registro",
                contents=f"Haz clic en el siguiente enlace para verificar tu correo: {verification_url}"
            )
            logging.info(f"Correo de verificación enviado a {email}.")
        except Exception as email_error:
            logging.error(f"[EMAIL001] Error al enviar el correo: {email_error}")
            return jsonify({'code': 'EMAIL001', 'message': 'Error al enviar el correo de verificación'}), 500

        return jsonify({'message': 'Usuario registrado, verifica tu correo electrónico'})
    except Error as db_error:
        logging.error(f'[DB002] Error al registrar usuario en la base de datos: {db_error}')
        return jsonify({'code': 'DB002', 'message': f'Error al registrar usuario: {str(db_error)}'}), 500
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
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()
        cursor.execute("UPDATE user SET email_verified = TRUE WHERE email = %s", (email,))
        connection.commit()
        logging.info(f"Correo {email} verificado en la base de datos.")

        return jsonify({'message': 'Correo verificado exitosamente'})
    except jwt.ExpiredSignatureError:
        logging.warning("[JWT001] El token ha expirado.")
        return jsonify({'code': 'JWT001', 'message': 'Enlace de verificación expirado'}), 400
    except jwt.InvalidTokenError:
        logging.error("[JWT002] El token es inválido.")
        return jsonify({'code': 'JWT002', 'message': 'Enlace de verificación inválido'}), 400
    except Exception as e:
        logging.error(f"[VERIFY001] Error desconocido en la verificación de correo: {e}")
        return jsonify({'code': 'VERIFY001', 'message': 'Error al verificar el correo'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))


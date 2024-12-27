import os
import logging
from flask import Flask, request, jsonify, redirect
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
CORS(app, resources={r"/*": {"origins": "*"}})  # Permitir todas las solicitudes de cualquier origen

# Configurar el log para depuración
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Configurar la conexión a la base de datos
def get_db_connection():
    """Establece la conexión con la base de datos."""
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
    """
    Registra un nuevo usuario.
    1. Recibe los datos del usuario en formato JSON.
    2. Hashea la contraseña.
    3. Inserta los datos en la base de datos.
    4. Genera un token de verificación y lo envía por correo.
    """
    data = request.get_json()
    logging.debug(f"Datos recibidos para registro: {data}")

    # Validación de datos
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

    # Conexión a la base de datos
    connection = get_db_connection()
    if not connection:
        return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

    cursor = connection.cursor()

    try:
        # Inserción en la base de datos
        cursor.execute(
            "INSERT INTO user (username, email, password, user_type, email_verified) VALUES (%s, %s, %s, %s, %s)",
            (username, email, hashed_password, user_type, False)
        )
        connection.commit()
        logging.info(f"Usuario {username} registrado en la base de datos.")

        # Generación del token de verificación
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
            # Eliminar el usuario de la base de datos si el correo no se envía
            cursor.execute("DELETE FROM user WHERE email = %s", (email,))
            connection.commit()
            return jsonify({'code': 'EMAIL001', 'message': 'Error al enviar el correo de verificación'}), 500

        return jsonify({'message': 'Usuario registrado exitosamente. Por favor, verifica tu correo electrónico para completar el registro.'})

    except Error as db_error:
        logging.error(f'[DB002] Error al registrar usuario en la base de datos: {db_error}')
        return jsonify({'code': 'DB002', 'message': f'Error al registrar usuario: {str(db_error)}'}), 500

    except Exception as e:
        logging.error(f"[REG003] Error inesperado: {e}")
        return jsonify({'code': 'REG003', 'message': 'Error inesperado durante el registro'}), 500

    finally:
        # Cerrar el cursor y la conexión
        cursor.close()
        connection.close()

@app.route('/verification_result')
def verification_result():
    """
    Renderiza la página de resultado de verificación.
    Esta ruta sirve el HTML para mostrar el resultado de la verificación.
    """
    return """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificación de Correo</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
</head>
<body>
    <div class="container d-flex align-items-center justify-content-center min-vh-100">
        <div class="card p-5 text-center shadow-lg" style="max-width: 500px;">
            <div class="card-body">
                <i id="status-icon" class="bi" style="font-size: 4rem;"></i>
                <h2 id="status-title" class="mt-3"></h2>
                <p id="status-message" class="mt-3"></p>
                <img src="/assets/images/Logo.png" alt="SkillSwap Logo" width="50" height="50" class="d-inline-block align-text-top">
                <a href="https://juanm555.github.io/SkillSwap/pages/auth/login.html" id="action-button" class="btn btn-primary mt-4">Iniciar Sesión</a>
            </div>
        </div>
    </div>

    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const status = urlParams.get('status');
        
        const statusIcon = document.getElementById('status-icon');
        const statusTitle = document.getElementById('status-title');
        const statusMessage = document.getElementById('status-message');
        const actionButton = document.getElementById('action-button');

        switch(status) {
            case 'success':
                statusIcon.classList.add('bi-check-circle-fill', 'text-success');
                statusTitle.textContent = '¡Verificación Exitosa!';
                statusMessage.textContent = 'Gracias por verificar tu correo electrónico. Ahora puedes disfrutar de todos los beneficios de SkillSwap.';
                actionButton.style.display = 'block';
                break;
            case 'expired':
                statusIcon.classList.add('bi-exclamation-triangle-fill', 'text-warning');
                statusTitle.textContent = '¡Enlace Expirado!';
                statusMessage.textContent = 'El enlace de verificación ha expirado. Por favor, solicita uno nuevo.';
                actionButton.style.display = 'none';
                break;
            case 'invalid':
                statusIcon.classList.add('bi-x-circle-fill', 'text-danger');
                statusTitle.textContent = '¡Enlace Inválido!';
                statusMessage.textContent = 'El enlace de verificación no es válido. Por favor, solicita uno nuevo.';
                actionButton.style.display = 'none';
                break;
            default:
                statusIcon.classList.add('bi-exclamation-triangle-fill', 'text-danger');
                statusTitle.textContent = '¡Error de Verificación!';
                statusMessage.textContent = 'Hubo un problema con la verificación de tu correo. Por favor, intenta nuevamente.';
                actionButton.style.display = 'none';
        }
    </script>
</body>
</html>
    """

@app.route('/verify', methods=['GET'])
def verify_email():
    """
    Verifica el correo electrónico del usuario utilizando un token.
    Redirige a la página de resultado de verificación según el caso.
    """
    token = request.args.get('token')
    logging.debug(f"Token recibido para verificación: {token}")

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']
        
        connection = get_db_connection()
        if not connection:
            return redirect('/verification_result?status=error')

        cursor = connection.cursor()
        cursor.execute("UPDATE user SET email_verified = TRUE WHERE email = %s", (email,))
        connection.commit()
        
        return redirect('/verification_result?status=success')

    except jwt.ExpiredSignatureError:
        logging.warning("[JWT001] El token ha expirado.")
        return redirect('/verification_result?status=expired')

    except jwt.InvalidTokenError:
        logging.error("[JWT002] El token es inválido.")
        return redirect('/verification_result?status=invalid')

    except Exception as e:
        logging.error(f"[VERIFY001] Error desconocido en la verificación de correo: {e}")
        return redirect('/verification_result?status=error')

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


@app.route('/recover_password', methods=['POST'])
def recover_password():
    """
    Recupera la contraseña de un usuario enviando un enlace de restablecimiento.
    1. Verifica si el correo existe.
    2. Genera un token de restablecimiento y lo envía por correo.
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        logging.warning("[RECOVER001] El correo es obligatorio.")
        return jsonify({'code': 'RECOVER001', 'message': 'El correo es obligatorio'}), 400

    # Verificar si el correo existe en la base de datos
    connection = get_db_connection()
    if not connection:
        return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

    cursor = connection.cursor()

    try:
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            logging.warning(f"[RECOVER002] El correo {email} no está registrado.")
            return jsonify({'code': 'RECOVER002', 'message': 'El correo no está registrado'}), 404

        # Generación del token para restablecer la contraseña
        token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
        logging.info(f"Token generado para {email}: {token}")

        # Configurar y enviar el correo de recuperación
        reset_url = f"https://proyecto-bs4m.onrender.com/reset-password?token={token}"
        try:
            yag = yagmail.SMTP(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))
            yag.send(
                to=email,
                subject="Restablece tu contraseña en SkillSwap",
                contents=f"Haz clic en el siguiente enlace para restablecer tu contraseña: {reset_url}"
            )
            logging.info(f"Correo de recuperación enviado a {email}.")
        except Exception as email_error:
            logging.error(f"[EMAIL002] Error al enviar el correo de recuperación: {email_error}")
            return jsonify({'code': 'EMAIL002', 'message': 'Error al enviar el correo de recuperación'}), 500

        return jsonify({'message': 'Correo de recuperación enviado exitosamente. Por favor, revisa tu correo electrónico para restablecer la contraseña.'})

    except Error as db_error:
        logging.error(f'[DB002] Error al acceder a la base de datos: {db_error}')
        return jsonify({'code': 'DB002', 'message': f'Error al acceder a la base de datos: {str(db_error)}'}), 500

    except Exception as e:
        logging.error(f"[RECOVER003] Error inesperado en la recuperación de contraseña: {e}")
        return jsonify({'code': 'RECOVER003', 'message': 'Error inesperado al procesar la solicitud'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """
    Permite al usuario restablecer su contraseña mediante un token.
    1. Verifica el token de restablecimiento.
    2. Permite cambiar la contraseña.
    """
    token = request.args.get('token')
    if request.method == 'GET':
        # Validar el token
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            email = decoded['email']
            # Mostrar la página para restablecer la contraseña (puedes mostrar un formulario aquí)
            return """
            <html>
                <body>
                    <h2>Restablecer Contraseña</h2>
                    <form action="/reset-password" method="POST">
                        <input type="hidden" name="token" value="{}">
                        <label for="newPassword">Nueva Contraseña:</label>
                        <input type="password" name="newPassword" required>
                        <button type="submit">Restablecer Contraseña</button>
                    </form>
                </body>
            </html>
            """.format(token)

        except jwt.ExpiredSignatureError:
            logging.warning("[JWT003] El token ha expirado.")
            return jsonify({'code': 'JWT003', 'message': 'El token ha expirado'}), 400

        except jwt.InvalidTokenError:
            logging.error("[JWT004] El token es inválido.")
            return jsonify({'code': 'JWT004', 'message': 'El token es inválido'}), 400

    elif request.method == 'POST':
        new_password = request.form.get('newPassword')
        token = request.form.get('token')

        if not new_password:
            return jsonify({'code': 'RECOVER004', 'message': 'La nueva contraseña es obligatoria'}), 400

        # Validar el token y obtener el correo
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            email = decoded['email']

            # Hashear la nueva contraseña
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Actualizar la contraseña en la base de datos
            connection = get_db_connection()
            if not connection:
                return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

            cursor = connection.cursor()
            cursor.execute("UPDATE user SET password = %s WHERE email = %s", (hashed_password, email))
            connection.commit()

            logging.info(f"Contraseña de {email} actualizada exitosamente.")
            return jsonify({'message': 'Contraseña restablecida con éxito. Ahora puedes iniciar sesión.'})

        except jwt.ExpiredSignatureError:
            logging.warning("[JWT003] El token ha expirado.")
            return jsonify({'code': 'JWT003', 'message': 'El token ha expirado'}), 400

        except jwt.InvalidTokenError:
            logging.error("[JWT004] El token es inválido.")
            return jsonify({'code': 'JWT004', 'message': 'El token es inválido'}), 400

        except Exception as e:
            logging.error(f"[RECOVER005] Error inesperado al restablecer la contraseña: {e}")
            return jsonify({'code': 'RECOVER005', 'message': 'Error inesperado al restablecer la contraseña'}), 500

    return jsonify({'code': 'RECOVER006', 'message': 'Método no permitido'}), 405


# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

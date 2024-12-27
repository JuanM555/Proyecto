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
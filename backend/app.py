import logging
import os
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, make_response
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import MultiDict

from database import db
from utils.activation_handler import activate_user_account
from utils.registration_handler import handle_registration
from utils.login_handler import handle_login, complete_mfa_login
from utils.session_handler import validate_session, destroy_session, get_session_user
from utils.password_reset_handler import request_password_reset, complete_password_reset, validate_reset_token
from utils.mfa_handler import setup_mfa, enable_mfa, disable_mfa, check_mfa_required
from password_reset_form import PasswordResetRequestForm, PasswordResetConfirmForm

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.environ['DATABASE_URI'],
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('SECRET_KEY', 'default_secret_key'),
    'RECAPTCHA_PUBLIC_KEY': os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'),
    'RECAPTCHA_PRIVATE_KEY': os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe')
})

db.init_app(app)
bcrypt = Bcrypt(app)
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "ngrok-skip-browser-warning"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     expose_headers="*")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

GENERIC_REG_ERROR = 'Registration failed. Please check your input and captcha.'
GENERIC_LOGIN_ERROR = 'Login failed. Please check your credentials.'

# Session cookie settings
SESSION_COOKIE_NAME = 'session_id'
SESSION_COOKIE_MAX_AGE = 86400  # 24 hours
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() in ['true', '1', 't']
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = None


def template_redirect(template_name):
    base_url = os.getenv('TEMPLATE_BASE_URL', '/')
    return redirect(f"{base_url}/templates/{template_name}")


def set_session_cookie(response, session_id):
    """Set secure session cookie on response."""
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        secure=SESSION_COOKIE_SECURE,
        httponly=SESSION_COOKIE_HTTPONLY,
        samesite=SESSION_COOKIE_SAMESITE
    )
    return response


def clear_session_cookie(response):
    """Clear session cookie on response."""
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


def get_session_id_from_request():
    """Get session ID from cookie or Authorization header."""
    # First try cookie
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        return session_id
    
    # Then try Authorization header (for cross-origin requests)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix
    
    return None


def get_current_user():
    """Get current user from session cookie or Authorization header."""
    session_id = get_session_id_from_request()
    if not session_id:
        return None
    return get_session_user(session_id)


# ==================== ROUTES ====================


@app.route('/')
def health_check():
    """Simple health check endpoint to verify API is working."""
    return jsonify({
        'status': 'ok',
        'message': 'API is running',
        'service': 'HelloKittyCMS Backend'
    }), 200


@app.route('/activate/<token>', methods=['GET'])
def activate_account(token):
    logging.info(f"Activation route accessed with token: {token}")
    template_name = activate_user_account(token)
    return template_redirect(template_name)


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    logging.info("Register route accessed")
    data = request.json
    response, status = handle_registration(data)
    return jsonify(response), status


# ==================== LOGIN ROUTES ====================

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    logging.info("Login route accessed")
    data = request.json
    
    response_data, status, session_id = handle_login(data)
    
    # Add session_id to response for cross-origin token-based auth
    if session_id:
        response_data['session_id'] = session_id
    
    response = make_response(jsonify(response_data), status)
    
    if session_id:
        set_session_cookie(response, session_id)
        logging.info(f"Session cookie set for user")
    
    return response


@app.route('/logout', methods=['POST'])
def logout():
    logging.info("Logout route accessed")
    session_id = get_session_id_from_request()
    
    if session_id:
        destroy_session(session_id)
        logging.info("Session destroyed")
    
    response = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    clear_session_cookie(response)
    return response


@app.route('/me', methods=['GET'])
def get_current_user_info():
    """Get current logged in user info."""
    user = get_current_user()
    
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'is_active': user.is_active,
            'mfa_enabled': user.mfa_enabled
        }
    }), 200


@app.route('/check-session', methods=['GET'])
def check_session():
    """Check if current session is valid."""
    session_id = get_session_id_from_request()
    
    if not session_id:
        return jsonify({'valid': False}), 200
    
    user_id = validate_session(session_id)
    return jsonify({'valid': user_id is not None}), 200


# ==================== MFA ROUTES ====================

@app.route('/mfa/setup', methods=['POST'])
def mfa_setup():
    """Initialize MFA setup - returns QR code and secret."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if user.mfa_enabled:
        return jsonify({'error': 'MFA is already enabled'}), 400
    
    response, error, status = setup_mfa(user.id)
    if error:
        return jsonify(error), status
    
    return jsonify(response), status


@app.route('/mfa/enable', methods=['POST'])
def mfa_enable():
    """Enable MFA after verifying code."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    if not data or 'secret' not in data or 'code' not in data:
        return jsonify({'error': 'Secret and code are required'}), 400
    
    response, status = enable_mfa(user.id, data['secret'], data['code'])
    return jsonify(response), status


@app.route('/mfa/disable', methods=['POST'])
def mfa_disable():
    """Disable MFA (requires valid code)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    if not data or 'code' not in data:
        return jsonify({'error': 'MFA code is required'}), 400
    
    response, status = disable_mfa(user.id, data['code'])
    return jsonify(response), status


@app.route('/mfa/verify-login', methods=['POST'])
@limiter.limit("5 per minute")
def mfa_verify_login():
    """Verify MFA code during login."""
    logging.info("MFA verify-login route accessed")
    data = request.json
    
    if not data or 'mfa_token' not in data or 'code' not in data:
        return jsonify({'error': 'MFA token and code are required'}), 400
    
    response_data, status, session_id = complete_mfa_login(data['mfa_token'], data['code'])
    
    # Add session_id to response for cross-origin token-based auth
    if session_id:
        response_data['session_id'] = session_id
    
    response = make_response(jsonify(response_data), status)
    
    if session_id:
        set_session_cookie(response, session_id)
        logging.info("Session cookie set after MFA verification")
    
    return response


@app.route('/mfa/status', methods=['GET'])
def mfa_status():
    """Check if MFA is enabled for current user."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'mfa_enabled': user.mfa_enabled
    }), 200


# ==================== PASSWORD RESET ROUTES ====================

@app.route('/password-reset/request', methods=['POST'])
@limiter.limit("3 per minute")
def password_reset_request():
    logging.info("Password reset request route accessed")
    data = request.json
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    # Validate form
    form_data = MultiDict(data)
    form = PasswordResetRequestForm(formdata=form_data, meta={'csrf': False})
    
    if not form.validate():
        logging.error(f"Password reset validation failed: {form.errors}")
        # Return generic message to prevent enumeration
        return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'}), 200
    
    response_data, status = request_password_reset(form.email.data)
    return jsonify(response_data), status


@app.route('/password-reset/validate', methods=['POST'])
def password_reset_validate():
    """Validate a reset token without using it."""
    logging.info("Password reset validate route accessed")
    data = request.json
    
    if not data or 'token' not in data:
        return jsonify({'valid': False}), 200
    
    user, error, status = validate_reset_token(data['token'])
    
    if error:
        return jsonify({'valid': False}), 200
    
    return jsonify({'valid': True, 'email': user.email}), 200


@app.route('/password-reset/confirm', methods=['POST'])
@limiter.limit("5 per minute")
def password_reset_confirm():
    logging.info("Password reset confirm route accessed")
    data = request.json
    
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    # Validate form
    form_data = MultiDict(data)
    form = PasswordResetConfirmForm(formdata=form_data, meta={'csrf': False})
    
    if not form.validate():
        logging.error(f"Password reset confirm validation failed: {form.errors}")
        # Return first error
        for field, errors in form.errors.items():
            if errors:
                return jsonify({'error': errors[0]}), 400
        return jsonify({'error': 'Invalid input'}), 400
    
    response_data, status = complete_password_reset(form.token.data, form.password.data)
    return jsonify(response_data), status


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    logging.warning("404 error encountered")
    return template_redirect('404.html')


@app.errorhandler(403)
def forbidden_error(error):
    logging.warning("403 error encountered")
    return template_redirect('403.html')


@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded: {e.description}")
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429


if __name__ == '__main__':
    with app.app_context():
        logging.info("Creating database tables")
        db.create_all()
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    logging.info(
        f"Starting Flask app in {'debug' if debug_mode else 'production'} mode")
    app.run(debug=debug_mode)

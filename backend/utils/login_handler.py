import logging
from datetime import datetime
from werkzeug.datastructures import MultiDict
from flask import request
from flask_bcrypt import Bcrypt

from config import PEPPER
from database import db
from database.models import User
from login_form import LoginForm
from utils.session_handler import create_session

GENERIC_LOGIN_ERROR = 'Login failed. Please check your credentials.'
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def validate_login_form(data):
    """Validate login form data using WTForms."""
    form_data = MultiDict(data)
    form = LoginForm(formdata=form_data, meta={'csrf': False})
    
    if form.validate():
        return form, None
    
    logging.error(f"Login validation failed: {form.errors}")
    return None, {'error': GENERIC_LOGIN_ERROR}


def check_account_lockout(user):
    """Check if account is locked due to too many failed attempts."""
    if user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        logging.warning(f"Login attempt on locked account: {user.email}")
        return True, remaining
    
    # Reset lockout if expired
    if user.locked_until and user.locked_until <= datetime.utcnow():
        user.locked_until = None
        user.failed_login_attempts = 0
        db.session.commit()
    
    return False, 0


def increment_failed_attempts(user):
    """Increment failed login attempts and lock account if threshold reached."""
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        from datetime import timedelta
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        logging.warning(f"Account locked due to {MAX_FAILED_ATTEMPTS} failed attempts: {user.email}")
    
    db.session.commit()


def reset_failed_attempts(user):
    """Reset failed login attempts after successful login."""
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()


def verify_password(user, password):
    """Verify password using bcrypt with pepper."""
    bcrypt = Bcrypt()
    return bcrypt.check_password_hash(user.password_hash, password + PEPPER)


def handle_login(data):
    """
    Handle user login request.
    Returns (response_dict, status_code, session_id or None)
    
    If MFA is enabled, returns mfa_required=True and user must verify with /mfa/verify-login
    """
    if not data:
        logging.error("No input data provided in login request")
        return {'error': GENERIC_LOGIN_ERROR}, 400, None
    
    # Validate form
    form, error_response = validate_login_form(data)
    if error_response:
        return error_response, 400, None
    
    email = form.email.data
    password = form.password.data
    
    # Find user
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Use constant time to prevent timing attacks
        logging.warning(f"Login attempt for non-existent email: {email}")
        # Simulate password check time
        Bcrypt().generate_password_hash("dummy_password")
        return {'error': GENERIC_LOGIN_ERROR}, 401, None
    
    # Check lockout
    is_locked, remaining_minutes = check_account_lockout(user)
    if is_locked:
        return {'error': f'Account locked. Try again in {remaining_minutes} minutes.'}, 403, None
    
    # Check if account is activated
    if not user.is_active:
        logging.warning(f"Login attempt on inactive account: {email}")
        return {'error': 'Account not activated. Please check your email.'}, 403, None
    
    # Verify password
    if not verify_password(user, password):
        logging.warning(f"Failed login attempt for: {email}")
        increment_failed_attempts(user)
        return {'error': GENERIC_LOGIN_ERROR}, 401, None
    
    # Password correct - check if MFA is required
    if user.mfa_enabled:
        logging.info(f"MFA required for user: {email}")
        # Return a temporary token for MFA verification
        import secrets
        mfa_token = secrets.token_urlsafe(32)
        # Store in session temporarily (we'll use a simple approach here)
        user.session_id = mfa_token  # Reuse session_id field temporarily
        db.session.commit()
        
        return {
            'mfa_required': True,
            'mfa_token': mfa_token,
            'message': 'Please enter your MFA code'
        }, 200, None
    
    # No MFA - complete login
    reset_failed_attempts(user)
    
    # Create session
    session_id = create_session(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    logging.info(f"User logged in successfully: {email}")
    
    return {
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'email': user.email,
            'mfa_enabled': user.mfa_enabled
        }
    }, 200, session_id


def complete_mfa_login(mfa_token, mfa_code):
    """
    Complete login after MFA verification.
    """
    from utils.mfa_handler import verify_totp_code
    
    # Find user by temporary mfa_token
    user = User.query.filter_by(session_id=mfa_token).first()
    
    if not user:
        logging.warning("MFA login attempt with invalid token")
        return {'error': 'Invalid or expired MFA session'}, 401, None
    
    # Verify MFA code
    if not verify_totp_code(user.totp_secret, mfa_code):
        logging.warning(f"MFA verification failed for user: {user.email}")
        return {'error': 'Invalid MFA code'}, 401, None
    
    # Clear temporary token
    user.session_id = None
    reset_failed_attempts(user)
    db.session.commit()
    
    # Create session
    from flask import request
    session_id = create_session(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    logging.info(f"MFA login completed for user: {user.email}")
    
    return {
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'email': user.email,
            'mfa_enabled': user.mfa_enabled
        }
    }, 200, session_id

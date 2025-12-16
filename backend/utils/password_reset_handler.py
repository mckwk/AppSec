import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta

from flask import request, url_for
from flask_bcrypt import Bcrypt
from jinja2 import Environment, FileSystemLoader
from mailersend import EmailBuilder

from config import PEPPER, ms
from database import db
from database.models import User, PasswordReset
from utils.session_handler import destroy_all_user_sessions

GENERIC_RESET_MESSAGE = 'If an account with that email exists, a password reset link has been sent.'
RESET_TOKEN_EXPIRY_HOURS = 1

template_loader = FileSystemLoader(searchpath="templates")
template_env = Environment(loader=template_loader)


def generate_reset_token():
    """Generate a cryptographically secure reset token."""
    return secrets.token_urlsafe(32)


def hash_token(token):
    """Hash the token using SHA-256 for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def request_password_reset(email):
    """
    Handle password reset request.
    Always returns success message to prevent user enumeration.
    """
    user = User.query.filter_by(email=email).first()
    
    if not user:
        logging.info(f"Password reset requested for non-existent email: {email}")
        # Return success to prevent enumeration
        return {'message': GENERIC_RESET_MESSAGE}, 200
    
    if not user.is_active:
        logging.info(f"Password reset requested for inactive account: {email}")
        return {'message': GENERIC_RESET_MESSAGE}, 200
    
    # Invalidate any existing reset tokens for this user
    existing_resets = PasswordReset.query.filter_by(user_id=user.id, used=False).all()
    for reset in existing_resets:
        reset.used = True
    
    # Generate new token
    token = generate_reset_token()
    token_hash = hash_token(token)
    expires_at = datetime.utcnow() + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)
    
    # Store hashed token
    password_reset = PasswordReset(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.session.add(password_reset)
    db.session.commit()
    
    # Send email with plaintext token
    reset_link = f"{os.getenv('FRONTEND_BASE_URL', 'http://localhost:5000')}/password_reset_confirm.html?token={token}"
    send_password_reset_email(reset_link, email)
    
    logging.info(f"Password reset token generated for: {email}")
    return {'message': GENERIC_RESET_MESSAGE}, 200


def validate_reset_token(token):
    """
    Validate a password reset token.
    Returns (user, error_response, status_code)
    """
    if not token:
        return None, {'error': 'Invalid reset token.'}, 400
    
    token_hash = hash_token(token)
    
    reset = PasswordReset.query.filter_by(token_hash=token_hash, used=False).first()
    
    if not reset:
        logging.warning(f"Invalid or used reset token attempted")
        return None, {'error': 'Invalid or expired reset token.'}, 400
    
    if reset.expires_at < datetime.utcnow():
        logging.warning(f"Expired reset token used for user_id: {reset.user_id}")
        return None, {'error': 'Reset token has expired.'}, 400
    
    return reset.user, None, None


def complete_password_reset(token, new_password):
    """
    Complete the password reset process.
    """
    user, error, status = validate_reset_token(token)
    
    if error:
        return error, status
    
    # Hash new password with pepper
    bcrypt = Bcrypt()
    password_hash = bcrypt.generate_password_hash(new_password + PEPPER).decode('utf-8')
    
    # Update user password
    user.password_hash = password_hash
    
    # Mark token as used
    token_hash = hash_token(token)
    reset = PasswordReset.query.filter_by(token_hash=token_hash).first()
    reset.used = True
    
    db.session.commit()
    
    # Destroy all existing sessions for security
    destroyed_count = destroy_all_user_sessions(user.id)
    
    logging.info(f"Password reset completed for: {user.email}, {destroyed_count} sessions destroyed")
    
    return {'message': 'Password reset successful. Please login with your new password.'}, 200


def render_email_template(template_name, **kwargs):
    """Render an email template."""
    template = template_env.get_template(template_name)
    return template.render(**kwargs)


def send_password_reset_email(reset_link, email):
    """Send password reset email."""
    try:
        logging.info(f"Sending password reset email to: {email}")
        
        html_content = render_email_template("password_reset_email_template.html", reset_link=reset_link)
        
        email_content = (EmailBuilder()
            .from_email(os.getenv('MAILERSEND_FROM_EMAIL', "default@example.com"), "Hello Kitty")
            .to_many([{"email": email, "name": email.split('@')[0]}])
            .subject("Reset Your Password")
            .html(html_content)
            .text(f"Click the link below to reset your password: {reset_link}")
            .build())
        
        ms.emails.send(email_content)
        logging.info(f"Password reset email successfully sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send password reset email to {email}: {e}, reset link: {reset_link}")

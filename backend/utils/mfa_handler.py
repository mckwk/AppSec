import logging
import pyotp
import qrcode
import io
import base64

from database import db
from database.models import User


def generate_totp_secret():
    """Generate a new TOTP secret for a user."""
    return pyotp.random_base32()


def get_totp_uri(email, secret):
    """Generate the provisioning URI for authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="HelloKittyCMS")


def generate_qr_code_base64(uri):
    """Generate a QR code image as base64 string."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_base64}"


def verify_totp_code(secret, code):
    """Verify a TOTP code against the secret."""
    if not secret or not code:
        return False
    
    totp = pyotp.TOTP(secret)
    # valid_window=1 allows codes from 30 seconds before/after
    return totp.verify(code, valid_window=1)


def setup_mfa(user_id):
    """
    Initialize MFA setup for a user.
    Returns the secret and QR code data.
    """
    user = User.query.get(user_id)
    if not user:
        return None, {'error': 'User not found'}, 404
    
    # Generate new secret (don't save yet - user needs to verify first)
    secret = generate_totp_secret()
    uri = get_totp_uri(user.email, secret)
    qr_code = generate_qr_code_base64(uri)
    
    logging.info(f"MFA setup initiated for user: {user.email}")
    
    return {
        'secret': secret,
        'qr_code': qr_code,
        'manual_entry_key': secret,  # For manual entry if QR doesn't work
        'message': 'Scan QR code with your authenticator app, then verify with a code'
    }, None, 200


def enable_mfa(user_id, secret, code):
    """
    Enable MFA after user verifies they can generate codes.
    """
    user = User.query.get(user_id)
    if not user:
        return {'error': 'User not found'}, 404
    
    if user.mfa_enabled:
        return {'error': 'MFA is already enabled'}, 400
    
    # Verify the code before enabling
    if not verify_totp_code(secret, code):
        logging.warning(f"MFA enable failed - invalid code for user: {user.email}")
        return {'error': 'Invalid verification code. Please try again.'}, 400
    
    # Save secret and enable MFA
    user.totp_secret = secret
    user.mfa_enabled = True
    db.session.commit()
    
    logging.info(f"MFA enabled for user: {user.email}")
    
    return {'message': 'MFA has been enabled successfully!'}, 200


def disable_mfa(user_id, code):
    """
    Disable MFA for a user (requires valid code).
    """
    user = User.query.get(user_id)
    if not user:
        return {'error': 'User not found'}, 404
    
    if not user.mfa_enabled:
        return {'error': 'MFA is not enabled'}, 400
    
    # Verify the code before disabling
    if not verify_totp_code(user.totp_secret, code):
        logging.warning(f"MFA disable failed - invalid code for user: {user.email}")
        return {'error': 'Invalid verification code'}, 400
    
    # Disable MFA
    user.totp_secret = None
    user.mfa_enabled = False
    db.session.commit()
    
    logging.info(f"MFA disabled for user: {user.email}")
    
    return {'message': 'MFA has been disabled'}, 200


def verify_mfa_login(user_id, code):
    """
    Verify MFA code during login.
    """
    user = User.query.get(user_id)
    if not user:
        return False
    
    if not user.mfa_enabled or not user.totp_secret:
        return True  # MFA not enabled, pass through
    
    is_valid = verify_totp_code(user.totp_secret, code)
    
    if is_valid:
        logging.info(f"MFA verification successful for user: {user.email}")
    else:
        logging.warning(f"MFA verification failed for user: {user.email}")
    
    return is_valid


def check_mfa_required(user_id):
    """Check if MFA is required for a user."""
    user = User.query.get(user_id)
    if not user:
        return False
    return user.mfa_enabled

import logging
import os
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, make_response, send_from_directory
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

# Content platform imports
from utils.content_handler import (
    create_post, get_posts, get_post_by_id, update_post, 
    delete_post, restore_post, search_posts
)
from utils.comment_handler import (
    create_comment, get_comments_for_post, delete_comment, restore_comment
)
from utils.rating_handler import rate_post, get_post_rating, get_user_rating
from utils.report_handler import report_content, get_pending_reports, get_all_reports, review_report
from utils.admin_handler import (
    get_all_users, get_user_by_id, update_user_role, 
    delete_user, restore_user, ban_user, unban_user,
    get_deleted_content, get_platform_stats
)
from utils.audit_handler import get_audit_logs, log_event, AuditActions
from utils.rbac_handler import is_admin, is_owner_or_admin
from utils.upload_handler import UPLOAD_FOLDER, get_upload_path

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


# ==================== CONTENT ROUTES ====================

@app.route('/posts', methods=['GET'])
def list_posts():
    """Get paginated list of posts (public)."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', None)
    user_id = request.args.get('user_id', None, type=int)
    
    result = get_posts(page=page, per_page=per_page, search_query=search, user_id=user_id)
    return jsonify(result), 200


@app.route('/posts', methods=['POST'])
@limiter.limit("10 per minute")
def create_new_post():
    """Create a new post (authenticated)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if not user.is_active or user.is_deleted:
        return jsonify({'error': 'Account is not active'}), 403
    
    # Handle multipart form data for file upload
    title = request.form.get('title') or (request.json.get('title') if request.is_json else None)
    content = request.form.get('content') or (request.json.get('content') if request.is_json else None)
    image_file = request.files.get('image')
    
    if not title:
        return jsonify({'error': 'Title is required'}), 400
    
    success, result = create_post(user.id, title, content, image_file)
    
    if success:
        return jsonify({'message': 'Post created successfully', 'post': result}), 201
    else:
        return jsonify({'error': result}), 400


@app.route('/posts/<int:post_id>', methods=['GET'])
def get_single_post(post_id):
    """Get a single post by ID (public)."""
    user = get_current_user()
    include_deleted = user and is_admin(user)
    
    success, result = get_post_by_id(post_id, include_deleted=include_deleted)
    
    if success:
        # Add user's rating if authenticated
        if user:
            result['user_rating'] = get_user_rating(user.id, post_id)
        return jsonify(result), 200
    else:
        return jsonify({'error': result}), 404


@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_existing_post(post_id):
    """Update a post (owner or admin)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    success, result = update_post(
        user.id, post_id, 
        title=data.get('title'),
        content=data.get('content'),
        is_admin=is_admin(user)
    )
    
    if success:
        return jsonify({'message': 'Post updated successfully', 'post': result}), 200
    else:
        return jsonify({'error': result}), 400


@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_existing_post(post_id):
    """Delete a post (owner or admin)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    success, message = delete_post(user.id, post_id, is_admin=is_admin(user))
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/posts/search', methods=['GET'])
@limiter.limit("30 per minute")
def search_all_posts():
    """Search posts by title or content (public)."""
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    result = search_posts(query, page=page, per_page=per_page)
    return jsonify(result), 200


# ==================== COMMENT ROUTES ====================

@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def get_post_comments(post_id):
    """Get comments for a post (public)."""
    user = get_current_user()
    include_deleted = user and is_admin(user)
    
    comments = get_comments_for_post(post_id, include_deleted=include_deleted)
    return jsonify({'comments': comments}), 200


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@limiter.limit("20 per minute")
def add_comment(post_id):
    """Add a comment to a post (authenticated)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if not user.is_active or user.is_deleted:
        return jsonify({'error': 'Account is not active'}), 403
    
    data = request.json
    if not data or 'content' not in data:
        return jsonify({'error': 'Comment content is required'}), 400
    
    success, result = create_comment(user.id, post_id, data['content'])
    
    if success:
        return jsonify({'message': 'Comment added successfully', 'comment': result}), 201
    else:
        return jsonify({'error': result}), 400


@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_single_comment(comment_id):
    """Delete a comment (owner or admin)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    success, message = delete_comment(user.id, comment_id, is_admin=is_admin(user))
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


# ==================== RATING ROUTES ====================

@app.route('/posts/<int:post_id>/rating', methods=['POST'])
@limiter.limit("30 per minute")
def rate_single_post(post_id):
    """Rate a post (authenticated)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if not user.is_active or user.is_deleted:
        return jsonify({'error': 'Account is not active'}), 403
    
    data = request.json
    if not data or 'value' not in data:
        return jsonify({'error': 'Rating value is required'}), 400
    
    success, result = rate_post(user.id, post_id, data['value'])
    
    if success:
        return jsonify({'message': 'Rating saved successfully', 'rating': result}), 200
    else:
        return jsonify({'error': result}), 400


@app.route('/posts/<int:post_id>/rating', methods=['GET'])
def get_single_post_rating(post_id):
    """Get rating statistics for a post (public)."""
    result = get_post_rating(post_id)
    
    # Include user's rating if authenticated
    user = get_current_user()
    if user:
        result['user_rating'] = get_user_rating(user.id, post_id)
    
    return jsonify(result), 200


# ==================== REPORT ROUTES ====================

@app.route('/reports', methods=['POST'])
@limiter.limit("10 per hour")
def submit_report():
    """Report content for moderation (authenticated)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if not user.is_active or user.is_deleted:
        return jsonify({'error': 'Account is not active'}), 403
    
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    success, result = report_content(
        user.id,
        post_id=data.get('post_id'),
        comment_id=data.get('comment_id'),
        reason=data.get('reason')
    )
    
    if success:
        return jsonify(result), 201
    else:
        return jsonify({'error': result}), 400


# ==================== ADMIN ROUTES ====================

@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Get platform statistics (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    stats = get_platform_stats()
    return jsonify(stats), 200


@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    """List all users (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    include_deleted = request.args.get('include_deleted', 'false').lower() == 'true'
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    result = get_all_users(include_deleted=include_deleted, page=page, per_page=per_page)
    return jsonify(result), 200


@app.route('/admin/users/<int:target_user_id>', methods=['GET'])
def admin_get_user(target_user_id):
    """Get user details (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    result = get_user_by_id(target_user_id, include_deleted=True)
    
    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/admin/users/<int:target_user_id>/role', methods=['PUT'])
def admin_update_user_role(target_user_id):
    """Update user role (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    if not data or 'role' not in data:
        return jsonify({'error': 'Role is required'}), 400
    
    success, message = update_user_role(user.id, target_user_id, data['role'])
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/users/<int:target_user_id>', methods=['DELETE'])
def admin_delete_user(target_user_id):
    """Delete user account (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = delete_user(user.id, target_user_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/users/<int:target_user_id>/restore', methods=['POST'])
def admin_restore_user(target_user_id):
    """Restore deleted user (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = restore_user(user.id, target_user_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/users/<int:target_user_id>/ban', methods=['POST'])
def admin_ban_user(target_user_id):
    """Ban user (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = ban_user(user.id, target_user_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/users/<int:target_user_id>/unban', methods=['POST'])
def admin_unban_user(target_user_id):
    """Unban user (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = unban_user(user.id, target_user_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/posts/<int:post_id>/restore', methods=['POST'])
def admin_restore_post(post_id):
    """Restore deleted post (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = restore_post(user.id, post_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/comments/<int:comment_id>/restore', methods=['POST'])
def admin_restore_comment(comment_id):
    """Restore deleted comment (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    success, message = restore_comment(user.id, comment_id)
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/reports', methods=['GET'])
def admin_list_reports():
    """List reports (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    status = request.args.get('status', 'pending')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    if status == 'pending':
        result = get_pending_reports(page=page, per_page=per_page)
    else:
        result = get_all_reports(status=status if status != 'all' else None, page=page, per_page=per_page)
    
    return jsonify(result), 200


@app.route('/admin/reports/<int:report_id>', methods=['PUT'])
def admin_review_report(report_id):
    """Review and act on a report (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    if not data or 'action' not in data:
        return jsonify({'error': 'Action is required'}), 400
    
    success, message = review_report(
        user.id, 
        report_id, 
        data['action'],
        delete_content=data.get('delete_content', False)
    )
    
    if success:
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@app.route('/admin/deleted', methods=['GET'])
def admin_get_deleted_content():
    """Get deleted content for restoration (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    content_type = request.args.get('type', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    result = get_deleted_content(content_type=content_type, page=page, per_page=per_page)
    return jsonify(result), 200


@app.route('/admin/audit', methods=['GET'])
def admin_get_audit_logs():
    """Get audit logs (admin only)."""
    user = get_current_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Admin access required'}), 403
    
    user_id_filter = request.args.get('user_id', None, type=int)
    action = request.args.get('action', None)
    resource_type = request.args.get('resource_type', None)
    limit = min(request.args.get('limit', 100, type=int), 500)
    offset = request.args.get('offset', 0, type=int)
    
    logs = get_audit_logs(
        user_id=user_id_filter,
        action=action,
        resource_type=resource_type,
        limit=limit,
        offset=offset
    )
    
    return jsonify({'logs': logs}), 200


# ==================== UPLOAD ROUTES ====================

@app.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    """Serve uploaded files (public)."""
    # Security: path traversal protection is handled by send_from_directory
    return send_from_directory(UPLOAD_FOLDER, filename)


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

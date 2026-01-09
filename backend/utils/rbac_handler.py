"""
Role-Based Access Control (RBAC) Handler
Provides decorators and utilities for permission checking.
"""
import logging
from functools import wraps
from flask import jsonify, request

# Role hierarchy
ROLES = {
    'guest': 0,
    'user': 1,
    'admin': 2
}


def get_role_level(role):
    """Get numeric level for a role."""
    return ROLES.get(role, 0)


def is_admin(user):
    """Check if user has admin role."""
    if not user:
        return False
    return user.role == 'admin'


def is_owner_or_admin(user, resource_user_id):
    """Check if user is owner of resource or has admin privileges."""
    if not user:
        return False
    if is_admin(user):
        return True
    return user.id == resource_user_id


def require_auth(get_current_user_func):
    """
    Decorator factory that requires user to be authenticated.
    
    Args:
        get_current_user_func: Function to get current user from request
    
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_func()
            if not user:
                logging.warning(f"Unauthorized access attempt to {request.endpoint}")
                return jsonify({'error': 'Authentication required'}), 401
            if not user.is_active:
                logging.warning(f"Inactive user {user.id} attempted to access {request.endpoint}")
                return jsonify({'error': 'Account is not active'}), 403
            if user.is_deleted:
                logging.warning(f"Deleted user {user.id} attempted to access {request.endpoint}")
                return jsonify({'error': 'Account has been deleted'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_role(role, get_current_user_func):
    """
    Decorator factory that requires user to have at least specified role.
    
    Args:
        role: Minimum required role ('user', 'admin')
        get_current_user_func: Function to get current user from request
    
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_func()
            if not user:
                logging.warning(f"Unauthorized access attempt to {request.endpoint}")
                return jsonify({'error': 'Authentication required'}), 401
            if not user.is_active:
                logging.warning(f"Inactive user {user.id} attempted to access {request.endpoint}")
                return jsonify({'error': 'Account is not active'}), 403
            if user.is_deleted:
                logging.warning(f"Deleted user {user.id} attempted to access {request.endpoint}")
                return jsonify({'error': 'Account has been deleted'}), 403
            
            required_level = get_role_level(role)
            user_level = get_role_level(user.role)
            
            if user_level < required_level:
                logging.warning(f"User {user.id} with role '{user.role}' denied access to {request.endpoint} (requires '{role}')")
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_resource_access(user, resource_user_id, action='modify'):
    """
    Check if user can access/modify a resource.
    
    Args:
        user: Current user object
        resource_user_id: ID of the user who owns the resource
        action: Description of action for logging
    
    Returns:
        Tuple (allowed: bool, error_response: tuple or None)
    """
    if not user:
        return False, (jsonify({'error': 'Authentication required'}), 401)
    
    if not is_owner_or_admin(user, resource_user_id):
        logging.warning(f"User {user.id} denied {action} access to resource owned by user {resource_user_id}")
        return False, (jsonify({'error': 'You do not have permission to perform this action'}), 403)
    
    return True, None

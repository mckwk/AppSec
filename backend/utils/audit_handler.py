"""
Audit Logging Handler
Provides security event and audit logging functionality.
"""
import json
import logging
from datetime import datetime
from flask import request
from database import db
from database.models import AuditLog


def log_event(user_id, action, resource_type=None, resource_id=None, details=None):
    """
    Log a security or audit event.
    
    Args:
        user_id: ID of user performing action (None for anonymous)
        action: Description of the action
        resource_type: Type of resource (e.g., 'post', 'comment', 'user')
        resource_id: ID of the affected resource
        details: Additional details as dict
    """
    try:
        # Get request context if available
        ip_address = None
        user_agent = None
        
        try:
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')[:255]
        except RuntimeError:
            # Outside of request context
            pass
        
        # Convert details to JSON string
        details_json = None
        if details:
            try:
                details_json = json.dumps(details)
            except (TypeError, ValueError):
                details_json = str(details)
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details_json,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
        # Also log to standard logger
        log_message = f"AUDIT: user={user_id} action={action}"
        if resource_type:
            log_message += f" resource_type={resource_type}"
        if resource_id:
            log_message += f" resource_id={resource_id}"
        if ip_address:
            log_message += f" ip={ip_address}"
        
        logging.info(log_message)
        
    except Exception as e:
        logging.error(f"Failed to create audit log: {e}")
        db.session.rollback()


def get_audit_logs(user_id=None, action=None, resource_type=None, 
                   start_date=None, end_date=None, limit=100, offset=0):
    """
    Retrieve audit logs with optional filtering.
    
    Args:
        user_id: Filter by user ID
        action: Filter by action (partial match)
        resource_type: Filter by resource type
        start_date: Filter by start date
        end_date: Filter by end date
        limit: Maximum number of results
        offset: Pagination offset
    
    Returns:
        List of audit log entries as dictionaries
    """
    query = AuditLog.query
    
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action.ilike(f'%{action}%'))
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    
    query = query.order_by(AuditLog.created_at.desc())
    query = query.offset(offset).limit(limit)
    
    logs = query.all()
    
    return [
        {
            'id': log.id,
            'user_id': log.user_id,
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'details': json.loads(log.details) if log.details else None,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'created_at': log.created_at.isoformat() if log.created_at else None
        }
        for log in logs
    ]


# Common audit actions
class AuditActions:
    # User actions
    USER_LOGIN = 'user.login'
    USER_LOGOUT = 'user.logout'
    USER_REGISTER = 'user.register'
    USER_PASSWORD_RESET = 'user.password_reset'
    USER_MFA_ENABLE = 'user.mfa.enable'
    USER_MFA_DISABLE = 'user.mfa.disable'
    
    # Content actions
    POST_CREATE = 'post.create'
    POST_UPDATE = 'post.update'
    POST_DELETE = 'post.delete'
    POST_RESTORE = 'post.restore'
    
    COMMENT_CREATE = 'comment.create'
    COMMENT_DELETE = 'comment.delete'
    COMMENT_RESTORE = 'comment.restore'
    
    RATING_CREATE = 'rating.create'
    RATING_UPDATE = 'rating.update'
    
    # Moderation actions
    REPORT_CREATE = 'report.create'
    REPORT_REVIEW = 'report.review'
    
    # Admin actions
    ADMIN_USER_DELETE = 'admin.user.delete'
    ADMIN_USER_RESTORE = 'admin.user.restore'
    ADMIN_USER_BAN = 'admin.user.ban'
    ADMIN_CONTENT_DELETE = 'admin.content.delete'
    ADMIN_CONTENT_RESTORE = 'admin.content.restore'

"""
Admin Handler
Handles administrative operations on users and content.
"""
import logging
from datetime import datetime
from database import db
from database.models import User, Post, Comment
from utils.audit_handler import log_event, AuditActions


def get_all_users(include_deleted=False, page=1, per_page=20):
    """
    Get all users for admin management.
    
    Args:
        include_deleted: Include soft-deleted users
        page: Page number
        per_page: Items per page
    
    Returns:
        Dict with users and pagination
    """
    query = User.query
    
    if not include_deleted:
        query = query.filter(User.is_deleted == False)
    
    query = query.order_by(User.created_at.desc())
    
    total = query.count()
    users = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'users': [
            {
                'id': u.id,
                'email': u.email,
                'role': u.role,
                'is_active': u.is_active,
                'is_deleted': u.is_deleted,
                'mfa_enabled': u.mfa_enabled,
                'created_at': u.created_at.isoformat() if u.created_at else None,
                'deleted_at': u.deleted_at.isoformat() if u.deleted_at else None,
                'post_count': u.posts.filter_by(is_deleted=False).count() if hasattr(u, 'posts') else 0,
                'comment_count': u.comments.filter_by(is_deleted=False).count() if hasattr(u, 'comments') else 0
            }
            for u in users
        ],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    }


def get_user_by_id(user_id, include_deleted=False):
    """
    Get user details by ID.
    """
    query = User.query.filter(User.id == user_id)
    
    if not include_deleted:
        query = query.filter(User.is_deleted == False)
    
    user = query.first()
    
    if not user:
        return None
    
    return {
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'is_active': user.is_active,
        'is_deleted': user.is_deleted,
        'mfa_enabled': user.mfa_enabled,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'deleted_at': user.deleted_at.isoformat() if user.deleted_at else None
    }


def update_user_role(admin_id, target_user_id, new_role):
    """
    Update a user's role.
    
    Args:
        admin_id: ID of the admin making the change
        target_user_id: ID of the user to update
        new_role: New role ('user' or 'admin')
    
    Returns:
        Tuple (success: bool, message: str)
    """
    if new_role not in ['user', 'admin']:
        return False, "Invalid role. Use 'user' or 'admin'"
    
    if admin_id == target_user_id:
        return False, "Cannot change your own role"
    
    user = User.query.filter(User.id == target_user_id, User.is_deleted == False).first()
    
    if not user:
        return False, "User not found"
    
    try:
        old_role = user.role
        user.role = new_role
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action='admin.user.role_change',
            resource_type='user',
            resource_id=target_user_id,
            details={'old_role': old_role, 'new_role': new_role}
        )
        
        logging.info(f"User {target_user_id} role changed from {old_role} to {new_role} by admin {admin_id}")
        
        return True, f"User role updated to {new_role}"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update user role: {e}")
        return False, "Failed to update user role"


def delete_user(admin_id, target_user_id):
    """
    Soft-delete a user account.
    
    Args:
        admin_id: ID of the admin performing deletion
        target_user_id: ID of the user to delete
    
    Returns:
        Tuple (success: bool, message: str)
    """
    if admin_id == target_user_id:
        return False, "Cannot delete your own account"
    
    user = User.query.filter(User.id == target_user_id, User.is_deleted == False).first()
    
    if not user:
        return False, "User not found"
    
    try:
        user.is_deleted = True
        user.deleted_at = datetime.utcnow()
        user.is_active = False  # Deactivate account
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.ADMIN_USER_DELETE,
            resource_type='user',
            resource_id=target_user_id,
            details={'email': user.email}
        )
        
        logging.info(f"User {target_user_id} soft-deleted by admin {admin_id}")
        
        return True, "User account deleted successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete user: {e}")
        return False, "Failed to delete user"


def restore_user(admin_id, target_user_id):
    """
    Restore a soft-deleted user account.
    
    Args:
        admin_id: ID of the admin performing restoration
        target_user_id: ID of the user to restore
    
    Returns:
        Tuple (success: bool, message: str)
    """
    user = User.query.filter(User.id == target_user_id, User.is_deleted == True).first()
    
    if not user:
        return False, "Deleted user not found"
    
    try:
        user.is_deleted = False
        user.deleted_at = None
        user.is_active = True  # Reactivate account
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.ADMIN_USER_RESTORE,
            resource_type='user',
            resource_id=target_user_id,
            details={'email': user.email}
        )
        
        logging.info(f"User {target_user_id} restored by admin {admin_id}")
        
        return True, "User account restored successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to restore user: {e}")
        return False, "Failed to restore user"


def ban_user(admin_id, target_user_id):
    """
    Ban a user (deactivate without deletion).
    
    Args:
        admin_id: ID of the admin performing ban
        target_user_id: ID of the user to ban
    
    Returns:
        Tuple (success: bool, message: str)
    """
    if admin_id == target_user_id:
        return False, "Cannot ban yourself"
    
    user = User.query.filter(User.id == target_user_id, User.is_deleted == False).first()
    
    if not user:
        return False, "User not found"
    
    if not user.is_active:
        return False, "User is already inactive"
    
    try:
        user.is_active = False
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.ADMIN_USER_BAN,
            resource_type='user',
            resource_id=target_user_id,
            details={'email': user.email}
        )
        
        logging.info(f"User {target_user_id} banned by admin {admin_id}")
        
        return True, "User banned successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to ban user: {e}")
        return False, "Failed to ban user"


def unban_user(admin_id, target_user_id):
    """
    Unban a user (reactivate account).
    
    Args:
        admin_id: ID of the admin performing unban
        target_user_id: ID of the user to unban
    
    Returns:
        Tuple (success: bool, message: str)
    """
    user = User.query.filter(User.id == target_user_id, User.is_deleted == False).first()
    
    if not user:
        return False, "User not found"
    
    if user.is_active:
        return False, "User is already active"
    
    try:
        user.is_active = True
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action='admin.user.unban',
            resource_type='user',
            resource_id=target_user_id,
            details={'email': user.email}
        )
        
        logging.info(f"User {target_user_id} unbanned by admin {admin_id}")
        
        return True, "User unbanned successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to unban user: {e}")
        return False, "Failed to unban user"


def get_deleted_content(content_type='all', page=1, per_page=20):
    """
    Get soft-deleted content for potential restoration.
    
    Args:
        content_type: 'posts', 'comments', 'users', or 'all'
        page: Page number
        per_page: Items per page
    
    Returns:
        Dict with deleted content
    """
    result = {'deleted': []}
    
    if content_type in ['posts', 'all']:
        posts = Post.query.filter(Post.is_deleted == True)\
            .order_by(Post.deleted_at.desc())\
            .limit(per_page if content_type == 'posts' else per_page // 3)\
            .all()
        
        for post in posts:
            result['deleted'].append({
                'type': 'post',
                'id': post.id,
                'title': post.title,
                'user_id': post.user_id,
                'user_email': post.user.email if post.user else None,
                'deleted_at': post.deleted_at.isoformat() if post.deleted_at else None,
                'deleted_by_id': post.deleted_by_id
            })
    
    if content_type in ['comments', 'all']:
        comments = Comment.query.filter(Comment.is_deleted == True)\
            .order_by(Comment.deleted_at.desc())\
            .limit(per_page if content_type == 'comments' else per_page // 3)\
            .all()
        
        for comment in comments:
            result['deleted'].append({
                'type': 'comment',
                'id': comment.id,
                'content': comment.content[:100],
                'post_id': comment.post_id,
                'user_id': comment.user_id,
                'user_email': comment.user.email if comment.user else None,
                'deleted_at': comment.deleted_at.isoformat() if comment.deleted_at else None,
                'deleted_by_id': comment.deleted_by_id
            })
    
    if content_type in ['users', 'all']:
        users = User.query.filter(User.is_deleted == True)\
            .order_by(User.deleted_at.desc())\
            .limit(per_page if content_type == 'users' else per_page // 3)\
            .all()
        
        for user in users:
            result['deleted'].append({
                'type': 'user',
                'id': user.id,
                'email': user.email,
                'deleted_at': user.deleted_at.isoformat() if user.deleted_at else None
            })
    
    return result


def get_platform_stats():
    """
    Get platform statistics for admin dashboard.
    """
    return {
        'users': {
            'total': User.query.filter(User.is_deleted == False).count(),
            'active': User.query.filter(User.is_deleted == False, User.is_active == True).count(),
            'admins': User.query.filter(User.is_deleted == False, User.role == 'admin').count()
        },
        'posts': {
            'total': Post.query.filter(Post.is_deleted == False).count(),
            'deleted': Post.query.filter(Post.is_deleted == True).count()
        },
        'comments': {
            'total': Comment.query.filter(Comment.is_deleted == False).count(),
            'deleted': Comment.query.filter(Comment.is_deleted == True).count()
        },
        'reports': {
            'pending': db.session.query(db.func.count()).select_from(
                db.session.query(db.text("1")).from_statement(
                    db.text("SELECT 1 FROM report WHERE status = 'pending'")
                ).subquery()
            ).scalar() or 0
        }
    }

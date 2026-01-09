"""
Comment Handler
Handles comment CRUD operations with security measures.
"""
import logging
import bleach
from datetime import datetime
from database import db
from database.models import Comment, Post
from utils.audit_handler import log_event, AuditActions

# Allowed HTML tags for comments (minimal)
ALLOWED_TAGS = ['b', 'i', 'u', 'strong', 'em']
MAX_COMMENT_LENGTH = 2000


def sanitize_comment(content):
    """
    Sanitize comment content to prevent XSS.
    
    Args:
        content: Raw comment content
    
    Returns:
        Sanitized content
    """
    if not content:
        return content
    
    return bleach.clean(content, tags=ALLOWED_TAGS, strip=True)[:MAX_COMMENT_LENGTH]


def create_comment(user_id, post_id, content):
    """
    Create a new comment on a post.
    
    Args:
        user_id: ID of the commenter
        post_id: ID of the post
        content: Comment content
    
    Returns:
        Tuple (success: bool, comment_data or error: dict/str)
    """
    # Validate content
    if not content or not content.strip():
        return False, "Comment content is required"
    
    clean_content = sanitize_comment(content.strip())
    if len(clean_content) < 1:
        return False, "Comment cannot be empty"
    
    # Check if post exists and is not deleted
    post = Post.query.filter(Post.id == post_id, Post.is_deleted == False).first()
    if not post:
        return False, "Post not found"
    
    try:
        comment = Comment(
            user_id=user_id,
            post_id=post_id,
            content=clean_content
        )
        
        db.session.add(comment)
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=user_id,
            action=AuditActions.COMMENT_CREATE,
            resource_type='comment',
            resource_id=comment.id,
            details={'post_id': post_id}
        )
        
        logging.info(f"Comment {comment.id} created by user {user_id} on post {post_id}")
        
        return True, {
            'id': comment.id,
            'post_id': comment.post_id,
            'user_id': comment.user_id,
            'user_email': comment.user.email if comment.user else None,
            'content': comment.content,
            'created_at': comment.created_at.isoformat() if comment.created_at else None
        }
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to create comment: {e}")
        return False, "Failed to create comment"


def get_comments_for_post(post_id, include_deleted=False):
    """
    Get all comments for a post.
    
    Args:
        post_id: Post ID
        include_deleted: Include deleted comments (admin only)
    
    Returns:
        List of comment dictionaries
    """
    query = Comment.query.filter(Comment.post_id == post_id)
    
    if not include_deleted:
        query = query.filter(Comment.is_deleted == False)
    
    query = query.order_by(Comment.created_at.asc())
    comments = query.all()
    
    return [
        {
            'id': c.id,
            'post_id': c.post_id,
            'user_id': c.user_id,
            'user_email': c.user.email if c.user else None,
            'content': c.content,
            'created_at': c.created_at.isoformat() if c.created_at else None,
            'is_deleted': c.is_deleted
        }
        for c in comments
    ]


def delete_comment(user_id, comment_id, is_admin=False):
    """
    Soft-delete a comment.
    
    Args:
        user_id: ID of user performing deletion
        comment_id: Comment ID to delete
        is_admin: Whether user is admin
    
    Returns:
        Tuple (success: bool, message: str)
    """
    comment = Comment.query.filter(Comment.id == comment_id, Comment.is_deleted == False).first()
    
    if not comment:
        return False, "Comment not found"
    
    # Check ownership
    if not is_admin and comment.user_id != user_id:
        return False, "You do not have permission to delete this comment"
    
    try:
        comment.is_deleted = True
        comment.deleted_at = datetime.utcnow()
        comment.deleted_by_id = user_id
        
        db.session.commit()
        
        # Audit log
        action = AuditActions.ADMIN_CONTENT_DELETE if is_admin and comment.user_id != user_id else AuditActions.COMMENT_DELETE
        log_event(
            user_id=user_id,
            action=action,
            resource_type='comment',
            resource_id=comment.id,
            details={'post_id': comment.post_id, 'original_owner': comment.user_id}
        )
        
        logging.info(f"Comment {comment.id} soft-deleted by user {user_id}")
        
        return True, "Comment deleted successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete comment: {e}")
        return False, "Failed to delete comment"


def restore_comment(admin_id, comment_id):
    """
    Restore a soft-deleted comment (admin only).
    
    Args:
        admin_id: ID of admin performing restore
        comment_id: Comment ID to restore
    
    Returns:
        Tuple (success: bool, message: str)
    """
    comment = Comment.query.filter(Comment.id == comment_id, Comment.is_deleted == True).first()
    
    if not comment:
        return False, "Deleted comment not found"
    
    try:
        comment.is_deleted = False
        comment.deleted_at = None
        comment.deleted_by_id = None
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.COMMENT_RESTORE,
            resource_type='comment',
            resource_id=comment.id
        )
        
        logging.info(f"Comment {comment.id} restored by admin {admin_id}")
        
        return True, "Comment restored successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to restore comment: {e}")
        return False, "Failed to restore comment"

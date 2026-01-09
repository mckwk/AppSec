"""
Rating Handler
Handles post ratings with one rating per user per post.
"""
import logging
from sqlalchemy import func
from database import db
from database.models import Rating, Post
from utils.audit_handler import log_event, AuditActions


def rate_post(user_id, post_id, value):
    """
    Rate a post or update existing rating.
    
    Args:
        user_id: ID of the rater
        post_id: ID of the post
        value: Rating value (1-5)
    
    Returns:
        Tuple (success: bool, rating_data or error: dict/str)
    """
    # Validate value
    try:
        value = int(value)
        if value < 1 or value > 5:
            return False, "Rating must be between 1 and 5"
    except (ValueError, TypeError):
        return False, "Invalid rating value"
    
    # Check if post exists and is not deleted
    post = Post.query.filter(Post.id == post_id, Post.is_deleted == False).first()
    if not post:
        return False, "Post not found"
    
    # Check for existing rating
    existing = Rating.query.filter(
        Rating.post_id == post_id,
        Rating.user_id == user_id
    ).first()
    
    try:
        if existing:
            # Update existing rating
            old_value = existing.value
            existing.value = value
            db.session.commit()
            
            # Audit log
            log_event(
                user_id=user_id,
                action=AuditActions.RATING_UPDATE,
                resource_type='rating',
                resource_id=existing.id,
                details={'post_id': post_id, 'old_value': old_value, 'new_value': value}
            )
            
            logging.info(f"Rating {existing.id} updated by user {user_id}: {old_value} -> {value}")
            
            return True, {
                'id': existing.id,
                'post_id': post_id,
                'value': value,
                'updated': True
            }
        else:
            # Create new rating
            rating = Rating(
                user_id=user_id,
                post_id=post_id,
                value=value
            )
            
            db.session.add(rating)
            db.session.commit()
            
            # Audit log
            log_event(
                user_id=user_id,
                action=AuditActions.RATING_CREATE,
                resource_type='rating',
                resource_id=rating.id,
                details={'post_id': post_id, 'value': value}
            )
            
            logging.info(f"Rating {rating.id} created by user {user_id} on post {post_id}")
            
            return True, {
                'id': rating.id,
                'post_id': post_id,
                'value': value,
                'updated': False
            }
            
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to rate post: {e}")
        return False, "Failed to save rating"


def get_post_rating(post_id):
    """
    Get rating statistics for a post.
    
    Args:
        post_id: Post ID
    
    Returns:
        Dict with rating statistics
    """
    result = db.session.query(
        func.avg(Rating.value).label('average'),
        func.count(Rating.id).label('count')
    ).filter(Rating.post_id == post_id).first()
    
    return {
        'post_id': post_id,
        'average': round(float(result.average), 1) if result.average else None,
        'count': result.count or 0
    }


def get_user_rating(user_id, post_id):
    """
    Get a specific user's rating for a post.
    
    Args:
        user_id: User ID
        post_id: Post ID
    
    Returns:
        Rating value or None
    """
    rating = Rating.query.filter(
        Rating.post_id == post_id,
        Rating.user_id == user_id
    ).first()
    
    return rating.value if rating else None


def delete_rating(user_id, post_id):
    """
    Delete a user's rating for a post.
    
    Args:
        user_id: User ID
        post_id: Post ID
    
    Returns:
        Tuple (success: bool, message: str)
    """
    rating = Rating.query.filter(
        Rating.post_id == post_id,
        Rating.user_id == user_id
    ).first()
    
    if not rating:
        return False, "Rating not found"
    
    try:
        db.session.delete(rating)
        db.session.commit()
        
        logging.info(f"Rating deleted by user {user_id} on post {post_id}")
        return True, "Rating deleted successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete rating: {e}")
        return False, "Failed to delete rating"

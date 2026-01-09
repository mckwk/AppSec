"""
Content Handler
Handles post CRUD operations with security measures.
"""
import logging
import bleach
from datetime import datetime
from sqlalchemy import or_
from database import db
from database.models import Post, User
from utils.upload_handler import validate_and_save_image, delete_upload
from utils.audit_handler import log_event, AuditActions

# Allowed HTML tags and attributes for sanitization
ALLOWED_TAGS = ['p', 'br', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}

# Pagination defaults
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50


def sanitize_content(content):
    """
    Sanitize user-provided content to prevent XSS.
    
    Args:
        content: Raw user content
    
    Returns:
        Sanitized content
    """
    if not content:
        return content
    
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )


def sanitize_title(title):
    """
    Sanitize post title (no HTML allowed).
    
    Args:
        title: Raw title
    
    Returns:
        Sanitized title
    """
    if not title:
        return title
    
    return bleach.clean(title, tags=[], strip=True)[:255]


def create_post(user_id, title, content=None, image_file=None):
    """
    Create a new post.
    
    Args:
        user_id: ID of the user creating the post
        title: Post title
        content: Post content (optional)
        image_file: Uploaded image file (optional)
    
    Returns:
        Tuple (success: bool, post_data or error: dict/str)
    """
    # Validate title
    if not title or not title.strip():
        return False, "Title is required"
    
    clean_title = sanitize_title(title.strip())
    if len(clean_title) < 3:
        return False, "Title must be at least 3 characters long"
    
    # Sanitize content
    clean_content = sanitize_content(content.strip()) if content else None
    
    # Handle image upload
    image_path = None
    if image_file:
        success, result, relative_path = validate_and_save_image(image_file)
        if not success:
            return False, result  # result contains error message
        image_path = relative_path
    
    try:
        post = Post(
            user_id=user_id,
            title=clean_title,
            content=clean_content,
            image_path=image_path
        )
        
        db.session.add(post)
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=user_id,
            action=AuditActions.POST_CREATE,
            resource_type='post',
            resource_id=post.id,
            details={'title': clean_title[:50]}
        )
        
        logging.info(f"Post {post.id} created by user {user_id}")
        
        return True, {
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'image_path': post.image_path,
            'created_at': post.created_at.isoformat() if post.created_at else None,
            'user_id': post.user_id
        }
        
    except Exception as e:
        db.session.rollback()
        # Clean up uploaded image if post creation failed
        if image_path:
            delete_upload(image_path)
        logging.error(f"Failed to create post: {e}")
        return False, "Failed to create post"


def get_posts(page=1, per_page=DEFAULT_PAGE_SIZE, search_query=None, 
              include_deleted=False, user_id=None):
    """
    Get paginated list of posts.
    
    Args:
        page: Page number (1-indexed)
        per_page: Items per page
        search_query: Optional search term
        include_deleted: Include soft-deleted posts (admin only)
        user_id: Filter by user ID (optional)
    
    Returns:
        Dict with posts list and pagination info
    """
    per_page = min(per_page, MAX_PAGE_SIZE)
    page = max(1, page)
    
    query = Post.query
    
    # Filter deleted posts
    if not include_deleted:
        query = query.filter(Post.is_deleted == False)
    
    # Filter by user
    if user_id:
        query = query.filter(Post.user_id == user_id)
    
    # Search (parameterized query - safe from SQL injection)
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(
            or_(
                Post.title.ilike(search_term),
                Post.content.ilike(search_term)
            )
        )
    
    # Order by newest first
    query = query.order_by(Post.created_at.desc())
    
    # Paginate
    total = query.count()
    posts = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'posts': [
            {
                'id': post.id,
                'title': post.title,
                'content': post.content[:200] + '...' if post.content and len(post.content) > 200 else post.content,
                'image_path': post.image_path,
                'created_at': post.created_at.isoformat() if post.created_at else None,
                'updated_at': post.updated_at.isoformat() if post.updated_at else None,
                'user_id': post.user_id,
                'user_email': post.user.email if post.user else None,
                'is_deleted': post.is_deleted,
                'rating_avg': get_post_rating_avg(post.id),
                'comment_count': post.comments.filter_by(is_deleted=False).count()
            }
            for post in posts
        ],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    }


def get_post_by_id(post_id, include_deleted=False):
    """
    Get a single post by ID.
    
    Args:
        post_id: Post ID
        include_deleted: Include if soft-deleted
    
    Returns:
        Tuple (success: bool, post_data or error: dict/str)
    """
    query = Post.query.filter(Post.id == post_id)
    
    if not include_deleted:
        query = query.filter(Post.is_deleted == False)
    
    post = query.first()
    
    if not post:
        return False, "Post not found"
    
    return True, {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'image_path': post.image_path,
        'created_at': post.created_at.isoformat() if post.created_at else None,
        'updated_at': post.updated_at.isoformat() if post.updated_at else None,
        'user_id': post.user_id,
        'user_email': post.user.email if post.user else None,
        'is_deleted': post.is_deleted,
        'deleted_at': post.deleted_at.isoformat() if post.deleted_at else None,
        'rating_avg': get_post_rating_avg(post.id),
        'comment_count': post.comments.filter_by(is_deleted=False).count()
    }


def update_post(user_id, post_id, title=None, content=None, is_admin=False, image_file=None):
    """
    Update an existing post.
    
    Args:
        user_id: ID of user making the update
        post_id: Post ID to update
        title: New title (optional)
        content: New content (optional)
        is_admin: Whether user is admin
        image_file: New image file (optional)
    
    Returns:
        Tuple (success: bool, post_data or error: dict/str)
    """
    post = Post.query.filter(Post.id == post_id, Post.is_deleted == False).first()
    
    if not post:
        return False, "Post not found"
    
    # Check ownership
    if not is_admin and post.user_id != user_id:
        return False, "You do not have permission to edit this post"
    
    # Update fields
    if title:
        clean_title = sanitize_title(title.strip())
        if len(clean_title) < 3:
            return False, "Title must be at least 3 characters long"
        post.title = clean_title
    
    if content is not None:
        post.content = sanitize_content(content.strip()) if content else None
    
    # Handle image upload
    if image_file:
        from utils.upload_handler import validate_and_save_image
        success, result, relative_path = validate_and_save_image(image_file)
        if success:
            post.image_path = relative_path
        else:
            return False, result  # result contains error message
    
    try:
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=user_id,
            action=AuditActions.POST_UPDATE,
            resource_type='post',
            resource_id=post.id,
            details={'updated_by_admin': is_admin}
        )
        
        logging.info(f"Post {post.id} updated by user {user_id}")
        
        return True, {
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'image_path': post.image_path,
            'updated_at': post.updated_at.isoformat() if post.updated_at else None
        }
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update post: {e}")
        return False, "Failed to update post"


def delete_post(user_id, post_id, is_admin=False):
    """
    Soft-delete a post.
    
    Args:
        user_id: ID of user performing deletion
        post_id: Post ID to delete
        is_admin: Whether user is admin
    
    Returns:
        Tuple (success: bool, message: str)
    """
    post = Post.query.filter(Post.id == post_id, Post.is_deleted == False).first()
    
    if not post:
        return False, "Post not found"
    
    # Check ownership
    if not is_admin and post.user_id != user_id:
        return False, "You do not have permission to delete this post"
    
    try:
        post.is_deleted = True
        post.deleted_at = datetime.utcnow()
        post.deleted_by_id = user_id
        
        db.session.commit()
        
        # Audit log
        action = AuditActions.ADMIN_CONTENT_DELETE if is_admin and post.user_id != user_id else AuditActions.POST_DELETE
        log_event(
            user_id=user_id,
            action=action,
            resource_type='post',
            resource_id=post.id,
            details={'original_owner': post.user_id}
        )
        
        logging.info(f"Post {post.id} soft-deleted by user {user_id}")
        
        return True, "Post deleted successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete post: {e}")
        return False, "Failed to delete post"


def restore_post(admin_id, post_id):
    """
    Restore a soft-deleted post (admin only).
    
    Args:
        admin_id: ID of admin performing restore
        post_id: Post ID to restore
    
    Returns:
        Tuple (success: bool, message: str)
    """
    post = Post.query.filter(Post.id == post_id, Post.is_deleted == True).first()
    
    if not post:
        return False, "Deleted post not found"
    
    try:
        post.is_deleted = False
        post.deleted_at = None
        post.deleted_by_id = None
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.ADMIN_CONTENT_RESTORE,
            resource_type='post',
            resource_id=post.id
        )
        
        logging.info(f"Post {post.id} restored by admin {admin_id}")
        
        return True, "Post restored successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to restore post: {e}")
        return False, "Failed to restore post"


def get_post_rating_avg(post_id):
    """Get average rating for a post."""
    from database.models import Rating
    from sqlalchemy import func
    
    result = db.session.query(func.avg(Rating.value)).filter(Rating.post_id == post_id).scalar()
    return round(float(result), 1) if result else None


def search_posts(query, page=1, per_page=DEFAULT_PAGE_SIZE):
    """
    Search posts by title or content.
    Uses parameterized queries for SQL injection protection.
    
    Args:
        query: Search query string
        page: Page number
        per_page: Items per page
    
    Returns:
        Dict with search results
    """
    if not query or len(query) < 2:
        return {'posts': [], 'pagination': {'page': 1, 'per_page': per_page, 'total': 0, 'pages': 0}}
    
    # Clean search query (remove special characters that could affect LIKE)
    clean_query = ''.join(c for c in query if c.isalnum() or c.isspace())[:100]
    
    return get_posts(page=page, per_page=per_page, search_query=clean_query)

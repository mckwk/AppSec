"""
Report Handler
Handles content reporting and moderation queue.
"""
import logging
import bleach
from datetime import datetime
from database import db
from database.models import Report, Post, Comment
from utils.audit_handler import log_event, AuditActions

MAX_REASON_LENGTH = 1000


def sanitize_reason(reason):
    """Sanitize report reason."""
    if not reason:
        return reason
    return bleach.clean(reason, tags=[], strip=True)[:MAX_REASON_LENGTH]


def report_content(user_id, post_id=None, comment_id=None, reason=None):
    """
    Report a post or comment for moderation.
    
    Args:
        user_id: ID of the reporter
        post_id: ID of the post to report (optional)
        comment_id: ID of the comment to report (optional)
        reason: Reason for the report
    
    Returns:
        Tuple (success: bool, report_data or error: dict/str)
    """
    # Validate that either post or comment is specified
    if not post_id and not comment_id:
        return False, "Must specify either a post or comment to report"
    
    if post_id and comment_id:
        return False, "Cannot report both post and comment at once"
    
    # Validate reason
    if not reason or not reason.strip():
        return False, "Report reason is required"
    
    clean_reason = sanitize_reason(reason.strip())
    if len(clean_reason) < 10:
        return False, "Please provide a more detailed reason (at least 10 characters)"
    
    # Verify the content exists
    if post_id:
        post = Post.query.filter(Post.id == post_id).first()
        if not post:
            return False, "Post not found"
        # Prevent self-reporting
        if post.user_id == user_id:
            return False, "You cannot report your own content"
    
    if comment_id:
        comment = Comment.query.filter(Comment.id == comment_id).first()
        if not comment:
            return False, "Comment not found"
        # Prevent self-reporting
        if comment.user_id == user_id:
            return False, "You cannot report your own content"
    
    # Check for duplicate reports
    existing = Report.query.filter(
        Report.reporter_user_id == user_id,
        Report.post_id == post_id if post_id else True,
        Report.comment_id == comment_id if comment_id else True,
        Report.status == 'pending'
    ).first()
    
    if existing:
        return False, "You have already reported this content"
    
    try:
        report = Report(
            post_id=post_id,
            comment_id=comment_id,
            reporter_user_id=user_id,
            reason=clean_reason,
            status='pending'
        )
        
        db.session.add(report)
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=user_id,
            action=AuditActions.REPORT_CREATE,
            resource_type='report',
            resource_id=report.id,
            details={
                'target_type': 'post' if post_id else 'comment',
                'target_id': post_id or comment_id
            }
        )
        
        logging.info(f"Report {report.id} created by user {user_id}")
        
        return True, {
            'id': report.id,
            'status': report.status,
            'message': 'Report submitted successfully. Our moderators will review it.'
        }
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to create report: {e}")
        return False, "Failed to submit report"


def get_pending_reports(page=1, per_page=20):
    """
    Get pending reports for admin review.
    
    Args:
        page: Page number
        per_page: Items per page
    
    Returns:
        Dict with reports and pagination
    """
    query = Report.query.filter(Report.status == 'pending')
    query = query.order_by(Report.created_at.asc())  # Oldest first
    
    total = query.count()
    reports = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'reports': [
            {
                'id': r.id,
                'post_id': r.post_id,
                'comment_id': r.comment_id,
                'reporter_user_id': r.reporter_user_id,
                'reporter_email': r.reporter.email if r.reporter else None,
                'reason': r.reason,
                'status': r.status,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'post_title': r.post.title if r.post else None,
                'comment_content': r.comment.content[:100] if r.comment else None,
                'target_user_id': r.post.user_id if r.post else (r.comment.user_id if r.comment else None)
            }
            for r in reports
        ],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    }


def get_all_reports(status=None, page=1, per_page=20):
    """
    Get all reports with optional status filter.
    """
    query = Report.query
    
    if status:
        query = query.filter(Report.status == status)
    
    query = query.order_by(Report.created_at.desc())
    
    total = query.count()
    reports = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        'reports': [
            {
                'id': r.id,
                'post_id': r.post_id,
                'comment_id': r.comment_id,
                'reporter_user_id': r.reporter_user_id,
                'reporter_email': r.reporter.email if r.reporter else None,
                'reason': r.reason,
                'status': r.status,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'reviewed_at': r.reviewed_at.isoformat() if r.reviewed_at else None,
                'reviewed_by_id': r.reviewed_by_id,
                'post_title': r.post.title if r.post else None,
                'comment_content': r.comment.content[:100] if r.comment else None
            }
            for r in reports
        ],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    }


def review_report(admin_id, report_id, action, delete_content=False):
    """
    Review and act on a report.
    
    Args:
        admin_id: ID of the admin reviewing
        report_id: Report ID
        action: 'approve' (take action) or 'dismiss'
        delete_content: If True and action is 'approve', delete the reported content
    
    Returns:
        Tuple (success: bool, message: str)
    """
    if action not in ['approve', 'dismiss', 'reviewed']:
        return False, "Invalid action. Use 'approve' or 'dismiss'"
    
    report = Report.query.filter(Report.id == report_id).first()
    
    if not report:
        return False, "Report not found"
    
    if report.status != 'pending':
        return False, "Report has already been reviewed"
    
    try:
        report.status = 'reviewed' if action == 'approve' else 'dismissed'
        report.reviewed_at = datetime.utcnow()
        report.reviewed_by_id = admin_id
        
        # Optionally delete the reported content
        if action == 'approve' and delete_content:
            if report.post_id:
                post = Post.query.get(report.post_id)
                if post and not post.is_deleted:
                    post.is_deleted = True
                    post.deleted_at = datetime.utcnow()
                    post.deleted_by_id = admin_id
                    logging.info(f"Post {post.id} deleted by admin {admin_id} after report review")
            
            if report.comment_id:
                comment = Comment.query.get(report.comment_id)
                if comment and not comment.is_deleted:
                    comment.is_deleted = True
                    comment.deleted_at = datetime.utcnow()
                    comment.deleted_by_id = admin_id
                    logging.info(f"Comment {comment.id} deleted by admin {admin_id} after report review")
        
        db.session.commit()
        
        # Audit log
        log_event(
            user_id=admin_id,
            action=AuditActions.REPORT_REVIEW,
            resource_type='report',
            resource_id=report.id,
            details={
                'action': action,
                'content_deleted': delete_content and action == 'approve'
            }
        )
        
        logging.info(f"Report {report.id} reviewed by admin {admin_id}: {action}")
        
        return True, f"Report {action}d successfully"
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to review report: {e}")
        return False, "Failed to review report"

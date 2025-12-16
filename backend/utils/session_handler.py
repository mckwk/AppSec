import logging
import secrets
from datetime import datetime, timedelta

from database import db
from database.models import Session


def create_session(user_id, ip_address=None, user_agent=None, expires_hours=24):
    """
    Create a new session for a user.
    Returns the session_id to be stored in cookie.
    """
    # Generate cryptographically secure session ID
    session_id = secrets.token_urlsafe(64)
    
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
    
    session = Session(
        session_id=session_id,
        user_id=user_id,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    db.session.add(session)
    db.session.commit()
    
    logging.info(f"Session created for user_id: {user_id}, expires: {expires_at}")
    return session_id


def validate_session(session_id):
    """
    Validate a session ID.
    Returns the user_id if valid, None if invalid or expired.
    """
    if not session_id:
        return None
    
    session = Session.query.filter_by(session_id=session_id).first()
    
    if not session:
        logging.debug(f"Session not found: {session_id[:20]}...")
        return None
    
    if session.expires_at < datetime.utcnow():
        logging.info(f"Session expired for user_id: {session.user_id}")
        # Clean up expired session
        db.session.delete(session)
        db.session.commit()
        return None
    
    return session.user_id


def get_session_user(session_id):
    """
    Get the user object for a valid session.
    Returns User object if valid, None otherwise.
    """
    if not session_id:
        return None
    
    session = Session.query.filter_by(session_id=session_id).first()
    
    if not session:
        return None
    
    if session.expires_at < datetime.utcnow():
        db.session.delete(session)
        db.session.commit()
        return None
    
    return session.user


def destroy_session(session_id):
    """
    Destroy a specific session (logout).
    """
    if not session_id:
        return False
    
    session = Session.query.filter_by(session_id=session_id).first()
    
    if session:
        user_id = session.user_id
        db.session.delete(session)
        db.session.commit()
        logging.info(f"Session destroyed for user_id: {user_id}")
        return True
    
    return False


def destroy_all_user_sessions(user_id):
    """
    Destroy all sessions for a user (used after password reset).
    """
    sessions = Session.query.filter_by(user_id=user_id).all()
    count = len(sessions)
    
    for session in sessions:
        db.session.delete(session)
    
    db.session.commit()
    logging.info(f"Destroyed {count} sessions for user_id: {user_id}")
    return count


def cleanup_expired_sessions():
    """
    Remove all expired sessions from the database.
    Should be called periodically.
    """
    now = datetime.utcnow()
    expired = Session.query.filter(Session.expires_at < now).all()
    count = len(expired)
    
    for session in expired:
        db.session.delete(session)
    
    db.session.commit()
    logging.info(f"Cleaned up {count} expired sessions")
    return count


def extend_session(session_id, hours=24):
    """
    Extend a session's expiration time (sliding expiration).
    """
    session = Session.query.filter_by(session_id=session_id).first()
    
    if session and session.expires_at > datetime.utcnow():
        session.expires_at = datetime.utcnow() + timedelta(hours=hours)
        db.session.commit()
        logging.debug(f"Session extended for user_id: {session.user_id}")
        return True
    
    return False

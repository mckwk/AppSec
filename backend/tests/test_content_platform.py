"""
Unit tests for HelloKittyCMS Content Platform
Tests for content, comment, rating, report, and admin handlers.
"""
import os
import sys
import unittest
import tempfile
import shutil
from io import BytesIO
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up test environment variables before importing app
os.environ['DATABASE_URI'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test_secret_key'
os.environ['MAILERSEND_API_KEY'] = 'test_api_key'
os.environ['ACTIVATION_SALT'] = 'test_salt'
os.environ['MAILERSEND_FROM_EMAIL'] = 'test@test.com'
os.environ['PEPPER'] = 'test_pepper'

from app import app, db
from database.models import User, Post, Comment, Rating, Report, AuditLog


class BaseTestCase(unittest.TestCase):
    """Base test case with database setup."""
    
    def setUp(self):
        """Set up test fixtures."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        
        self.app = app
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        db.create_all()
        
        # Create test users
        self.regular_user = User(
            email='user@test.com',
            password_hash='$2b$12$test_hash',
            is_active=True,
            role='user'
        )
        self.admin_user = User(
            email='admin@test.com',
            password_hash='$2b$12$test_hash',
            is_active=True,
            role='admin'
        )
        
        db.session.add(self.regular_user)
        db.session.add(self.admin_user)
        db.session.commit()
    
    def tearDown(self):
        """Tear down test fixtures."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


class TestContentHandler(BaseTestCase):
    """Tests for content_handler.py"""
    
    def test_sanitize_title_removes_html(self):
        """Test that HTML is stripped from titles."""
        from utils.content_handler import sanitize_title
        
        result = sanitize_title('<script>alert("xss")</script>Hello')
        self.assertEqual(result, 'alert("xss")Hello')
        
        result = sanitize_title('<b>Bold</b> Title')
        self.assertEqual(result, 'Bold Title')
    
    def test_sanitize_content_allows_safe_html(self):
        """Test that safe HTML tags are allowed in content."""
        from utils.content_handler import sanitize_content
        
        # Safe tags should be preserved
        result = sanitize_content('<p>Hello <b>World</b></p>')
        self.assertIn('<p>', result)
        self.assertIn('<b>', result)
        
        # Script tags should be removed
        result = sanitize_content('<script>alert("xss")</script>Text')
        self.assertNotIn('<script>', result)
        self.assertIn('Text', result)
    
    def test_create_post_requires_title(self):
        """Test that post creation requires a title."""
        from utils.content_handler import create_post
        
        success, error = create_post(self.regular_user.id, '', 'content')
        self.assertFalse(success)
        self.assertIn('required', error.lower())
    
    def test_create_post_success(self):
        """Test successful post creation."""
        from utils.content_handler import create_post
        
        success, result = create_post(
            self.regular_user.id, 
            'Test Title', 
            'Test content'
        )
        
        self.assertTrue(success)
        self.assertIn('id', result)
        self.assertEqual(result['title'], 'Test Title')
        
        # Verify in database
        post = Post.query.get(result['id'])
        self.assertIsNotNone(post)
        self.assertEqual(post.user_id, self.regular_user.id)
    
    def test_get_posts_pagination(self):
        """Test posts pagination."""
        from utils.content_handler import create_post, get_posts
        
        # Create 15 posts
        for i in range(15):
            create_post(self.regular_user.id, f'Post {i}', f'Content {i}')
        
        # Get first page
        result = get_posts(page=1, per_page=10)
        self.assertEqual(len(result['posts']), 10)
        self.assertEqual(result['pagination']['total'], 15)
        self.assertEqual(result['pagination']['pages'], 2)
        
        # Get second page
        result = get_posts(page=2, per_page=10)
        self.assertEqual(len(result['posts']), 5)
    
    def test_search_posts_parameterized(self):
        """Test search with parameterized queries (SQL injection prevention)."""
        from utils.content_handler import create_post, search_posts
        
        # Create posts
        create_post(self.regular_user.id, 'Hello World', 'content')
        create_post(self.regular_user.id, 'Goodbye World', 'content')
        
        # Normal search
        result = search_posts('Hello')
        self.assertEqual(len(result['posts']), 1)
        
        # SQL injection attempt - should return no results (cleaned query)
        result = search_posts("'; DROP TABLE post; --")
        # Query should be sanitized, not cause error
        self.assertIsInstance(result['posts'], list)
    
    def test_delete_post_ownership(self):
        """Test that users can only delete their own posts."""
        from utils.content_handler import create_post, delete_post
        
        # Create post as regular user
        success, post = create_post(self.regular_user.id, 'Test', 'content')
        post_id = post['id']
        
        # Create another user
        other_user = User(
            email='other@test.com',
            password_hash='hash',
            is_active=True,
            role='user'
        )
        db.session.add(other_user)
        db.session.commit()
        
        # Other user cannot delete
        success, message = delete_post(other_user.id, post_id, is_admin=False)
        self.assertFalse(success)
        
        # Owner can delete
        success, message = delete_post(self.regular_user.id, post_id, is_admin=False)
        self.assertTrue(success)
    
    def test_admin_can_delete_any_post(self):
        """Test that admins can delete any post."""
        from utils.content_handler import create_post, delete_post
        
        # Create post as regular user
        success, post = create_post(self.regular_user.id, 'Test', 'content')
        post_id = post['id']
        
        # Admin can delete
        success, message = delete_post(self.admin_user.id, post_id, is_admin=True)
        self.assertTrue(success)


class TestCommentHandler(BaseTestCase):
    """Tests for comment_handler.py"""
    
    def setUp(self):
        super().setUp()
        # Create a test post
        self.test_post = Post(
            user_id=self.regular_user.id,
            title='Test Post',
            content='Test content'
        )
        db.session.add(self.test_post)
        db.session.commit()
    
    def test_create_comment_sanitizes_content(self):
        """Test that comment content is sanitized."""
        from utils.comment_handler import create_comment
        
        success, result = create_comment(
            self.regular_user.id,
            self.test_post.id,
            '<script>alert("xss")</script>Safe text'
        )
        
        self.assertTrue(success)
        self.assertNotIn('<script>', result['content'])
        self.assertIn('Safe text', result['content'])
    
    def test_create_comment_requires_content(self):
        """Test that empty comments are rejected."""
        from utils.comment_handler import create_comment
        
        success, error = create_comment(
            self.regular_user.id,
            self.test_post.id,
            ''
        )
        
        self.assertFalse(success)
        self.assertIn('required', error.lower())
    
    def test_create_comment_on_deleted_post_fails(self):
        """Test that comments on deleted posts fail."""
        from utils.comment_handler import create_comment
        
        # Delete the post
        self.test_post.is_deleted = True
        db.session.commit()
        
        success, error = create_comment(
            self.regular_user.id,
            self.test_post.id,
            'Comment on deleted post'
        )
        
        self.assertFalse(success)
        self.assertIn('not found', error.lower())


class TestRatingHandler(BaseTestCase):
    """Tests for rating_handler.py"""
    
    def setUp(self):
        super().setUp()
        self.test_post = Post(
            user_id=self.regular_user.id,
            title='Test Post',
            content='Test content'
        )
        db.session.add(self.test_post)
        db.session.commit()
    
    def test_rate_post_valid_range(self):
        """Test that ratings must be 1-5."""
        from utils.rating_handler import rate_post
        
        # Invalid: 0
        success, error = rate_post(self.regular_user.id, self.test_post.id, 0)
        self.assertFalse(success)
        
        # Invalid: 6
        success, error = rate_post(self.regular_user.id, self.test_post.id, 6)
        self.assertFalse(success)
        
        # Valid: 3
        success, result = rate_post(self.regular_user.id, self.test_post.id, 3)
        self.assertTrue(success)
        self.assertEqual(result['value'], 3)
    
    def test_rate_post_updates_existing(self):
        """Test that rating the same post updates existing rating."""
        from utils.rating_handler import rate_post, get_user_rating
        
        # First rating
        success, result = rate_post(self.regular_user.id, self.test_post.id, 3)
        self.assertTrue(success)
        self.assertFalse(result['updated'])
        
        # Update rating
        success, result = rate_post(self.regular_user.id, self.test_post.id, 5)
        self.assertTrue(success)
        self.assertTrue(result['updated'])
        
        # Verify only one rating exists
        user_rating = get_user_rating(self.regular_user.id, self.test_post.id)
        self.assertEqual(user_rating, 5)
        
        ratings_count = Rating.query.filter_by(
            user_id=self.regular_user.id,
            post_id=self.test_post.id
        ).count()
        self.assertEqual(ratings_count, 1)
    
    def test_get_post_rating_average(self):
        """Test average rating calculation."""
        from utils.rating_handler import rate_post, get_post_rating
        
        # Add ratings from multiple users
        user2 = User(email='user2@test.com', password_hash='hash', is_active=True)
        user3 = User(email='user3@test.com', password_hash='hash', is_active=True)
        db.session.add_all([user2, user3])
        db.session.commit()
        
        rate_post(self.regular_user.id, self.test_post.id, 5)
        rate_post(user2.id, self.test_post.id, 4)
        rate_post(user3.id, self.test_post.id, 3)
        
        result = get_post_rating(self.test_post.id)
        self.assertEqual(result['average'], 4.0)  # (5+4+3)/3 = 4
        self.assertEqual(result['count'], 3)


class TestReportHandler(BaseTestCase):
    """Tests for report_handler.py"""
    
    def setUp(self):
        super().setUp()
        self.test_post = Post(
            user_id=self.regular_user.id,
            title='Test Post',
            content='Test content'
        )
        db.session.add(self.test_post)
        db.session.commit()
    
    def test_report_content_requires_reason(self):
        """Test that reports require a reason."""
        from utils.report_handler import report_content
        
        # Short reason rejected
        success, error = report_content(
            self.admin_user.id,
            post_id=self.test_post.id,
            reason='too short'
        )
        self.assertFalse(success)
        
        # Valid reason
        success, result = report_content(
            self.admin_user.id,
            post_id=self.test_post.id,
            reason='This post contains inappropriate content and should be reviewed.'
        )
        self.assertTrue(success)
    
    def test_cannot_report_own_content(self):
        """Test that users cannot report their own content."""
        from utils.report_handler import report_content
        
        success, error = report_content(
            self.regular_user.id,  # Post owner
            post_id=self.test_post.id,
            reason='Trying to report my own post for attention.'
        )
        
        self.assertFalse(success)
        self.assertIn('own content', error.lower())
    
    def test_duplicate_report_prevented(self):
        """Test that duplicate reports are prevented."""
        from utils.report_handler import report_content
        
        # First report
        success, result = report_content(
            self.admin_user.id,
            post_id=self.test_post.id,
            reason='This is a valid reason for reporting content.'
        )
        self.assertTrue(success)
        
        # Duplicate report
        success, error = report_content(
            self.admin_user.id,
            post_id=self.test_post.id,
            reason='Another report for the same content.'
        )
        self.assertFalse(success)
        self.assertIn('already reported', error.lower())


class TestAdminHandler(BaseTestCase):
    """Tests for admin_handler.py"""
    
    def test_update_user_role(self):
        """Test updating user role."""
        from utils.admin_handler import update_user_role
        
        # Make regular user an admin
        success, message = update_user_role(
            self.admin_user.id,
            self.regular_user.id,
            'admin'
        )
        self.assertTrue(success)
        
        # Verify
        updated_user = User.query.get(self.regular_user.id)
        self.assertEqual(updated_user.role, 'admin')
    
    def test_cannot_change_own_role(self):
        """Test that admins cannot change their own role."""
        from utils.admin_handler import update_user_role
        
        success, error = update_user_role(
            self.admin_user.id,
            self.admin_user.id,
            'user'
        )
        self.assertFalse(success)
        self.assertIn('own role', error.lower())
    
    def test_delete_and_restore_user(self):
        """Test soft delete and restore of user."""
        from utils.admin_handler import delete_user, restore_user
        
        # Delete user
        success, message = delete_user(self.admin_user.id, self.regular_user.id)
        self.assertTrue(success)
        
        # Verify deleted
        user = User.query.get(self.regular_user.id)
        self.assertTrue(user.is_deleted)
        self.assertFalse(user.is_active)
        
        # Restore user
        success, message = restore_user(self.admin_user.id, self.regular_user.id)
        self.assertTrue(success)
        
        # Verify restored
        user = User.query.get(self.regular_user.id)
        self.assertFalse(user.is_deleted)
        self.assertTrue(user.is_active)


class TestUploadHandler(BaseTestCase):
    """Tests for upload_handler.py"""
    
    def setUp(self):
        super().setUp()
        # Create temp upload directory
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        super().tearDown()
        # Clean up temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_allowed_file_extensions(self):
        """Test that only allowed file extensions are accepted."""
        from utils.upload_handler import allowed_file
        
        # Allowed
        self.assertTrue(allowed_file('image.png'))
        self.assertTrue(allowed_file('image.jpg'))
        self.assertTrue(allowed_file('image.jpeg'))
        self.assertTrue(allowed_file('image.gif'))
        self.assertTrue(allowed_file('image.webp'))
        
        # Not allowed
        self.assertFalse(allowed_file('script.php'))
        self.assertFalse(allowed_file('malware.exe'))
        self.assertFalse(allowed_file('document.pdf'))
        self.assertFalse(allowed_file('noextension'))
    
    def test_generate_safe_filename(self):
        """Test safe filename generation."""
        from utils.upload_handler import generate_safe_filename
        
        # Normal filename
        result = generate_safe_filename('test.jpg')
        self.assertTrue(result.endswith('.jpg'))
        self.assertNotEqual(result, 'test.jpg')  # Should be unique
        
        # Malicious filename
        result = generate_safe_filename('../../../etc/passwd.jpg')
        self.assertNotIn('..', result)
        self.assertNotIn('/', result)
    
    def test_validate_file_size(self):
        """Test file size validation."""
        from utils.upload_handler import validate_file_size
        
        # Small file - OK
        small_file = BytesIO(b'x' * 1000)
        is_valid, size, error = validate_file_size(small_file, max_size=5000)
        self.assertTrue(is_valid)
        
        # Large file - rejected
        large_file = BytesIO(b'x' * 10000)
        is_valid, size, error = validate_file_size(large_file, max_size=5000)
        self.assertFalse(is_valid)
        self.assertIn('too large', error.lower())
        
        # Empty file - rejected
        empty_file = BytesIO(b'')
        is_valid, size, error = validate_file_size(empty_file)
        self.assertFalse(is_valid)
        self.assertIn('empty', error.lower())


class TestRBACHandler(BaseTestCase):
    """Tests for rbac_handler.py"""
    
    def test_is_admin(self):
        """Test admin role check."""
        from utils.rbac_handler import is_admin
        
        self.assertTrue(is_admin(self.admin_user))
        self.assertFalse(is_admin(self.regular_user))
        self.assertFalse(is_admin(None))
    
    def test_is_owner_or_admin(self):
        """Test owner/admin permission check."""
        from utils.rbac_handler import is_owner_or_admin
        
        # Admin can access anything
        self.assertTrue(is_owner_or_admin(self.admin_user, self.regular_user.id))
        
        # User can access own resources
        self.assertTrue(is_owner_or_admin(self.regular_user, self.regular_user.id))
        
        # User cannot access others' resources
        self.assertFalse(is_owner_or_admin(self.regular_user, self.admin_user.id))
        
        # None user cannot access anything
        self.assertFalse(is_owner_or_admin(None, self.regular_user.id))


class TestAuditHandler(BaseTestCase):
    """Tests for audit_handler.py"""
    
    def test_log_event_creates_record(self):
        """Test that log_event creates audit log record."""
        from utils.audit_handler import log_event
        
        log_event(
            user_id=self.regular_user.id,
            action='test.action',
            resource_type='test',
            resource_id=1,
            details={'key': 'value'}
        )
        
        # Verify log was created
        log = AuditLog.query.filter_by(action='test.action').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user_id, self.regular_user.id)
        self.assertEqual(log.resource_type, 'test')
    
    def test_get_audit_logs_filtering(self):
        """Test audit log filtering."""
        from utils.audit_handler import log_event, get_audit_logs
        
        # Create logs
        log_event(self.regular_user.id, 'action1', 'post', 1)
        log_event(self.admin_user.id, 'action2', 'comment', 2)
        log_event(self.regular_user.id, 'action3', 'post', 3)
        
        # Filter by user
        logs = get_audit_logs(user_id=self.regular_user.id)
        self.assertEqual(len(logs), 2)
        
        # Filter by resource type
        logs = get_audit_logs(resource_type='comment')
        self.assertEqual(len(logs), 1)


class TestAPIEndpoints(BaseTestCase):
    """Integration tests for API endpoints."""
    
    def test_posts_endpoint_public(self):
        """Test that posts endpoint is accessible without auth."""
        response = self.client.get('/posts')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('posts', data)
        self.assertIn('pagination', data)
    
    def test_create_post_requires_auth(self):
        """Test that creating post requires authentication."""
        response = self.client.post('/posts', json={
            'title': 'Test Post',
            'content': 'Test content'
        })
        self.assertEqual(response.status_code, 401)
    
    def test_admin_endpoints_require_admin(self):
        """Test that admin endpoints require admin role."""
        # Without auth
        response = self.client.get('/admin/users')
        self.assertEqual(response.status_code, 403)
        
        response = self.client.get('/admin/stats')
        self.assertEqual(response.status_code, 403)
        
        response = self.client.get('/admin/reports')
        self.assertEqual(response.status_code, 403)


if __name__ == '__main__':
    unittest.main(verbosity=2)

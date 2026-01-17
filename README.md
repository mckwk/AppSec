# HelloKittyCMS

A secure content management platform developed as part of the Application Security course. 

## Overview

HelloKittyCMS is a web-based content management system implementing industry-standard security practices. The platform enables user registration with email verification, multi-factor authentication, content publishing with media uploads, and comprehensive administrative controls.

## Features

### Authentication and User Management
- User registration with email-based account activation
- Secure login with session management
- Account lockout after failed authentication attempts
- Time-based one-time password (TOTP) two-factor authentication
- Password reset functionality via email

### Content Management
- Post creation with optional image attachments
- Post editing and deletion (soft-delete)
- Comment system with moderation support
- Star-based rating system (1-5 scale)
- Full-text search across posts

### Administration
- Role-based access control (User, Administrator)
- User management (role assignment, ban, delete, restore)
- Content moderation and report review
- Deleted content restoration
- Audit log viewer with filtering capabilities

### Security Implementation
- Cross-Site Scripting (XSS) prevention via HTML sanitization
- SQL injection protection through parameterized queries
- Secure file upload with content-based validation
- Rate limiting on all API endpoints
- Comprehensive audit logging

## Technology Stack

**Backend**
- Python 3.8+
- Flask web framework
- SQLAlchemy ORM
- Flask-Bcrypt for password hashing
- Pillow for image processing

**Frontend**
- HTML5 / CSS3
- Vanilla JavaScript
- Responsive design

## Installation

### Prerequisites
- Python 3.8 or higher
- MailerSend account for email delivery
- Google reCAPTCHA keys

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Configure the environment variables in `.env`:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Application secret key |
| `DATABASE_URI` | Database connection string |
| `MAILERSEND_API_KEY` | MailerSend API key |
| `MAILERSEND_FROM_EMAIL` | Sender email address |
| `RECAPTCHA_SECRET_KEY` | reCAPTCHA secret key |
| `PEPPER` | Password hashing pepper |

Start the application:

```bash
python app.py
```

### Frontend Setup

```bash
cd frontend
cp config.js.example config.js
```

Update `API_BASE_URL` in `config.js` to point to your backend instance.

## Project Structure

```
├── backend/
│   ├── app.py                 # Application entry point
│   ├── database/              # Database models
│   ├── utils/                 # Business logic handlers
│   ├── templates/             # Email templates
│   └── uploads/               # User-uploaded files
├── frontend/
│   ├── index.html             # Registration
│   ├── login.html             # Authentication
│   ├── feed.html              # Content feed
│   ├── admin.html             # Administration panel
│   └── static/                # CSS and assets
└── specifications/            # Technical documentation
```


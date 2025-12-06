from flask import Flask, request, jsonify, url_for, render_template, send_from_directory, redirect
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
import os
from flask_cors import CORS
from database import db
from database.models import User
from mailersend import MailerSendClient, EmailBuilder
import jinja2
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URI', f"sqlite:///{os.path.abspath('database/users.db')}"),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('SECRET_KEY', 'default_secret_key')
})

ms = MailerSendClient(api_key=os.getenv('MAILERSEND_API_KEY'))

db.init_app(app)
bcrypt = Bcrypt(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
CORS(app)

template_loader = jinja2.FileSystemLoader(searchpath="templates")
template_env = jinja2.Environment(loader=template_loader)

def generate_activation_link(email):
    token = serializer.dumps(email, salt=os.getenv('ACTIVATION_SALT', 'email-activation'))
    return token, url_for('activate_account', token=token, _external=True)

def send_activation_email(activation_link, email="placeholder@email.com"):
    try:
        template = template_env.get_template("activation_email_template.html")
        html_content = template.render(activation_link=activation_link)

        email_content = (EmailBuilder()
                         .from_email(os.getenv('MAILERSEND_FROM_EMAIL', "default@example.com"), "Hello Kitty")
                         .to_many([{ "email": email, "name": email.split('@')[0] }])
                         .subject("Activate Your Account")
                         .html(html_content)
                         .text(f"Click the link below to activate your account: {activation_link}")
                         .build())
        response = ms.emails.send(email_content)
        print(f"Activation email sent to {email}, link: {activation_link}")
    except Exception as e:
        print(f"Failed to send activation email to {email}: {e}")

def ensure_database_exists():
    db_path = os.getenv('DATABASE_URI', f"sqlite:///{os.path.abspath('database/users.db')}").replace('sqlite:///', '')
    if not os.path.exists(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with open(db_path, 'w') as f:
            pass

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/activate/<token>', methods=['GET'])
def activate_account(token):
    try:
        email = serializer.loads(token, salt=os.getenv('ACTIVATION_SALT'), max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user and not user.is_active:
            user.is_active = True
            user.activation_token = None
            user.activation_expires_at = None
            db.session.commit()
            return redirect(f"{os.getenv('TEMPLATE_BASE_URL')}/templates/activation_success.html")
        else:
            return redirect(f"{os.getenv('TEMPLATE_BASE_URL')}/templates/invalid_token.html")
    except Exception:
        return redirect(f"{os.getenv('TEMPLATE_BASE_URL')}/templates/invalid_token.html")

@app.errorhandler(404)
def not_found_error(error):
    return redirect(f"{os.getenv('TEMPLATE_BASE_URL')}/templates/404.html")

@app.errorhandler(403)
def forbidden_error(error):
    return redirect(f"{os.getenv('TEMPLATE_BASE_URL')}/templates/403.html")

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    marketing_acc = data.get('marketing_acc', False)

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email is already registered.'}), 400

    # Hash the password
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    # Generate activation token and link
    token, activation_link = generate_activation_link(email)
    expiration = datetime.now() + timedelta(hours=24)

    # Create user
    user = User(
        email=email,
        password_hash=password_hash,
        activation_token=token,
        activation_expires_at=expiration,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        marketing_acc=marketing_acc
    )
    db.session.add(user)
    db.session.commit()

    # Send activation email (placeholder)
    send_activation_email(activation_link, email)

    return jsonify({'message': 'User registered. Please check your email to activate your account.'}), 201

if __name__ == '__main__':
    ensure_database_exists()
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
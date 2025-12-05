from flask import Flask, request, jsonify, url_for
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
import os
from flask_cors import CORS
from database import db
from database.models import User

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': f"sqlite:///{os.path.abspath('database/users.db')}",
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('SECRET_KEY', 'default_secret_key')
})

db.init_app(app)
bcrypt = Bcrypt(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
CORS(app, origins=["https://app-sec-virid.vercel.app/", "https://pulverable-kaydence-modular.ngrok-free.dev"])

def generate_activation_link(email):
    token = serializer.dumps(email, salt='email-activation')
    return token, url_for('activate', token=token, _external=True)

def send_activation_email(activation_link, email="placeholder@email.com"):
    # Placeholder for sending email logic
    print(f'Send activation email to {email} with link: {activation_link}')

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
    expiration = datetime.utcnow() + timedelta(hours=24)

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

@app.route('/activate/<token>', methods=['GET'])
def activate(token):
    try:
        email = serializer.loads(token, salt='email-activation', max_age=86400)
    except Exception:
        return jsonify({'error': 'Invalid token.'}), 400

    user = User.query.filter_by(email=email, activation_token=token).first()
    if not user:
        return jsonify({'error': 'Invalid token.'}), 400

    user.is_active = True
    user.activation_token = None
    user.activation_expires_at = None
    db.session.commit()

    return jsonify({'message': 'Account activated successfully.'}), 200

@app.route('/')
def home():
    return jsonify({"message": "Backend is running"})

if __name__ == '__main__':
    os.makedirs(os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')), exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
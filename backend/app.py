import os
from datetime import datetime, timedelta
import logging

import jinja2
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, RecaptchaField
from itsdangerous import URLSafeTimedSerializer
from mailersend import EmailBuilder, MailerSendClient
from werkzeug.datastructures import MultiDict
from wtforms import BooleanField, PasswordField, StringField, validators

from database import db
from database.models import User
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

app = Flask(__name__)
app.config.update({
    # 'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URI', f"sqlite:///{os.path.abspath('database/users.db')}"),
    'SQLALCHEMY_DATABASE_URI': os.environ['DATABASE_URI'],
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('SECRET_KEY', 'default_secret_key'),
    'RECAPTCHA_PUBLIC_KEY': os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'),
    'RECAPTCHA_PRIVATE_KEY': os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe')
})

ms = MailerSendClient(api_key=os.getenv('MAILERSEND_API_KEY'))
db.init_app(app)
bcrypt = Bcrypt(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
CORS(app, resources={r"*": {"origins": "*"}})
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
template_loader = jinja2.FileSystemLoader(searchpath="templates")
template_env = jinja2.Environment(loader=template_loader)
PEPPER = os.getenv('PEPPER', 'default_pepper')


class RegistrationForm(FlaskForm):
    email = StringField(
        'Email',
        [
            validators.DataRequired(),
            validators.Email()
        ]
    )

    # zaawansowana polityka hasła
    password = PasswordField(
        'Password',
        [
            validators.DataRequired(),
            validators.Length(min=8, message='Password must be at least 8 characters long.'),
            validators.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$',
                message='Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.'
            ),
        ]
    )

    # potwierdzenie hasła walidowane po stronie backendu
    confirm_password = PasswordField(
        'Confirm Password',
        [
            validators.DataRequired(),
            validators.EqualTo('password', message='Passwords must match.')
        ]
    )

    marketing_acc = BooleanField('Marketing Consent')
    recaptcha = RecaptchaField()


def generate_activation_link(email):
    token = serializer.dumps(
        email,
        salt=os.getenv('ACTIVATION_SALT', 'email-activation')
    )
    return token, url_for('activate_account', token=token, _external=True)


def send_activation_email(activation_link, email="placeholder@email.com"):
    try:
        template = template_env.get_template("activation_email_template.html")
        html_content = template.render(activation_link=activation_link)

        email_content = (EmailBuilder()
                         .from_email(os.getenv('MAILERSEND_FROM_EMAIL', "default@example.com"), "Hello Kitty")
                         .to_many([{"email": email, "name": email.split('@')[0]}])
                         .subject("Activate Your Account")
                         .html(html_content)
                         .text(f"Click the link below to activate your account: {activation_link}")
                         .build())
        ms.emails.send(email_content)
        logging.info(f"Activation email sent to {email}, link: {activation_link}")
    except Exception as e:
        logging.error(
            f"Failed to send activation email to {email}: {e}, activation link: {activation_link}"
        )


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/activate/<token>', methods=['GET'])
def activate_account(token):
    try:
        email = serializer.loads(
            token,
            salt=os.getenv('ACTIVATION_SALT'),
            max_age=86400  # 24 hours in seconds
        )
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


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.json
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    form_data = MultiDict(data)
    form = RegistrationForm(formdata=form_data, meta={'csrf': False})

    if form.validate():
        email = form.email.data
        password = form.password.data
        marketing_acc = form.marketing_acc.data

        if User.query.filter_by(email=email).first():
            # specjalnie ogólny komunikat
            return jsonify({'error': 'Registration failed.'}), 400

        password_hash = bcrypt.generate_password_hash(
            password + PEPPER
        ).decode('utf-8')

        token, activation_link = generate_activation_link(email)
        expiration = datetime.now() + timedelta(hours=24)

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

        send_activation_email(activation_link, email)
        return jsonify(
            {
                'message': 'User registered. Please check your email to activate your account.'
            }
        ), 201
    else:
        return jsonify(
            {
                'error': 'Invalid input or captcha.',
                'details': form.errors
            }
        ), 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)

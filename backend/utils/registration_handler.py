import logging
from datetime import datetime, timedelta
from werkzeug.datastructures import MultiDict
from flask import request
from flask_bcrypt import Bcrypt

from config import PEPPER
from database import db
from database.models import User
from registration_form import RegistrationForm
from utils.activation_handler import generate_activation_link, send_activation_email

GENERIC_REG_ERROR = 'Registration failed. Please check your input and captcha.'

def validate_registration_form(data):
    form_data = MultiDict(data)
    form = RegistrationForm(formdata=form_data, meta={'csrf': False})
    if form.validate():
        return form, None
    logging.error(f"Registration failed due to invalid input: {form.errors}")
    email_errors = form.errors.get('email', [])
    domain_blacklisted = any('Email domain is not allowed.' in msg for msg in email_errors)
    if domain_blacklisted:
        return None, {'error': 'Email domain is not allowed.'}
    return None, {'error': GENERIC_REG_ERROR}

def check_existing_user(email):
    if User.query.filter_by(email=email).first():
        logging.warning(f"Registration failed: Email {email} already exists")
        return {'error': GENERIC_REG_ERROR}
    return None

def create_user(form):
    email = form.email.data
    password = form.password.data
    marketing_acc = form.marketing_acc.data

    password_hash = Bcrypt().generate_password_hash(password + PEPPER).decode('utf-8')
    token, activation_link = generate_activation_link(email)
    expiration = datetime.utcnow() + timedelta(hours=24)

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

    logging.info(f"User {email} registered successfully")
    send_activation_email(activation_link, email)
    return {'message': 'User registered. Please check your email to activate your account.'}, 201

def handle_registration(data):
    if not data:
        logging.error("No input data provided in registration request")
        return {'error': GENERIC_REG_ERROR}, 400

    form, error_response = validate_registration_form(data)
    if error_response:
        return error_response, 400

    existing_user_error = check_existing_user(form.email.data)
    if existing_user_error:
        return existing_user_error, 400

    return create_user(form)
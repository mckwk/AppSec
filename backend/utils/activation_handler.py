import logging
import os
from datetime import datetime
from flask import url_for
from jinja2 import Environment, FileSystemLoader
from mailersend import EmailBuilder

from config import serializer, ms, template_env, ACTIVATION_SALT
from database.models import User
from database import db

template_loader = FileSystemLoader(searchpath="templates")
template_env = Environment(loader=template_loader)

GENERIC_REG_ERROR = 'Registration failed. Please check your input and captcha.'

def generate_token(email):
    return serializer.dumps(email, salt=ACTIVATION_SALT)

def decode_token(token):
    return serializer.loads(token, salt=ACTIVATION_SALT, max_age=86400)

def render_email_template(template_name, **kwargs):
    template = template_env.get_template(template_name)
    return template.render(**kwargs)

def build_email_content(activation_link, email):
    html_content = render_email_template("activation_email_template.html", activation_link=activation_link)
    return (EmailBuilder()
            .from_email(os.getenv('MAILERSEND_FROM_EMAIL', "default@example.com"), "Hello Kitty")
            .to_many([{ "email": email, "name": email.split('@')[0] }])
            .subject("Activate Your Account")
            .html(html_content)
            .text(f"Click the link below to activate your account: {activation_link}")
            .build())

def generate_activation_link(email):
    logging.info(f"Generating activation link for email: {email}")
    token = generate_token(email)
    logging.debug(f"Generated token: {token}")
    return token, url_for('activate_account', token=token, _external=True)

def send_activation_email(activation_link, email="placeholder@email.com"):
    try:
        logging.info(f"Sending activation email to: {email}")
        email_content = build_email_content(activation_link, email)
        ms.emails.send(email_content)
        logging.info(f"Activation email successfully sent to {email}")
    except Exception as e:
        logging.error(
            f"Failed to send activation email to {email}: {e}, activation link: {activation_link}"
        )

def activate_user_account(token):
    try:
        email = decode_token(token)
        logging.info(f"Token decoded successfully for email: {email}")
        user = User.query.filter_by(email=email).first()
        if not user:
            logging.warning(f"No user found for email: {email}")
            return 'invalid_token.html'

        if user.activation_token != token:
            logging.error(f"Invalid activation token for user {email}")
            return 'invalid_token.html'

        if user.activation_expires_at and user.activation_expires_at > datetime.utcnow():
            if not user.is_active:
                activate_user(user)
                logging.info(f"User {email} activated successfully")
                return 'activation_success.html'
            else:
                logging.warning(f"User {email} already activated")
                return 'invalid_token.html'
        else:
            logging.warning(f"Activation token expired for user {email}")
            return 'invalid_token.html'
    except Exception as e:
        logging.error(f"Error during account activation: {e}")
        return 'invalid_token.html'

def activate_user(user):
    user.is_active = True
    user.activation_token = None
    user.activation_expires_at = None
    db.session.commit()
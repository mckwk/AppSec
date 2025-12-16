import logging

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import PasswordField, StringField, validators


class LoginForm(FlaskForm):
    """Login form with email, password, and reCAPTCHA validation."""
    
    email = StringField(
        'Email',
        [
            validators.DataRequired(message='Email is required.'),
            validators.Email(message='Invalid email format.')
        ]
    )

    password = PasswordField(
        'Password',
        [
            validators.DataRequired(message='Password is required.')
        ]
    )

    recaptcha = RecaptchaField()

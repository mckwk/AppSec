import logging

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import PasswordField, StringField, validators


class PasswordResetRequestForm(FlaskForm):
    """Form for requesting a password reset."""
    
    email = StringField(
        'Email',
        [
            validators.DataRequired(message='Email is required.'),
            validators.Email(message='Invalid email format.')
        ]
    )

    recaptcha = RecaptchaField()


class PasswordResetConfirmForm(FlaskForm):
    """Form for setting a new password."""
    
    token = StringField(
        'Token',
        [
            validators.DataRequired(message='Reset token is required.')
        ]
    )

    password = PasswordField(
        'Password',
        [
            validators.DataRequired(message='Password is required.'),
            validators.Length(
                min=8, message='Password must be at least 8 characters long.'),
            validators.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$',
                message='Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.'
            ),
        ]
    )

    confirm_password = PasswordField(
        'Confirm Password',
        [
            validators.DataRequired(message='Password confirmation is required.'),
            validators.EqualTo('password', message='Passwords must match.')
        ]
    )

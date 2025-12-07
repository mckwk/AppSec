import logging

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import BooleanField, PasswordField, StringField, validators
from wtforms.validators import ValidationError


class RegistrationForm(FlaskForm):
    email = StringField(
        'Email',
        [
            validators.DataRequired(),
            validators.Email()
        ]
    )

    password = PasswordField(
        'Password',
        [
            validators.DataRequired(),
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
            validators.DataRequired(),
            validators.EqualTo('password', message='Passwords must match.')
        ]
    )

    marketing_acc = BooleanField('Marketing Consent')
    recaptcha = RecaptchaField()

    def validate_email(self, field):
        blacklist = {'amu.edu.pl', 'outlook.com'}
        try:
            domain = field.data.split('@', 1)[1].lower()
        except (IndexError, AttributeError):
            return

        if domain in blacklist:
            logging.warning(
                f"Registration attempt with blacklisted email domain: {domain}")
            raise ValidationError('Email domain is not allowed.')

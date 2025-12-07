import os
from itsdangerous import URLSafeTimedSerializer
from mailersend import MailerSendClient
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

load_dotenv()

# Shared configurations
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
ACTIVATION_SALT = os.getenv('ACTIVATION_SALT', 'email-activation')
PEPPER = os.getenv('PEPPER', '')

# Serializer for token generation
serializer = URLSafeTimedSerializer(SECRET_KEY)

# MailerSend client
ms = MailerSendClient(api_key=os.getenv('MAILERSEND_API_KEY'))

# Jinja2 template environment
template_loader = FileSystemLoader(searchpath="templates")
template_env = Environment(loader=template_loader)
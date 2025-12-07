import logging
import os
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database import db
from utils.activation_handler import activate_user_account
from utils.registration_handler import handle_registration

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.environ['DATABASE_URI'],
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.getenv('SECRET_KEY', 'default_secret_key'),
    'RECAPTCHA_PUBLIC_KEY': os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'),
    'RECAPTCHA_PRIVATE_KEY': os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe')
})

db.init_app(app)
bcrypt = Bcrypt(app)
CORS(app, resources={r"*": {"origins": "*"}})
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

GENERIC_REG_ERROR = 'Registration failed. Please check your input and captcha.'

def template_redirect(template_name):
    base_url = os.getenv('TEMPLATE_BASE_URL', '/')
    return redirect(f"{base_url}/templates/{template_name}")

# Routes

@app.route('/')
def home():
    logging.info("Home route accessed")
    return render_template('home.html')


@app.route('/activate/<token>', methods=['GET'])
def activate_account(token):
    logging.info(f"Activation route accessed with token: {token}")
    template_name = activate_user_account(token)
    return template_redirect(template_name)


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    logging.info("Register route accessed")
    data = request.json
    response, status = handle_registration(data)
    return jsonify(response), status


@app.errorhandler(404)
def not_found_error(error):
    logging.warning("404 error encountered")
    return template_redirect('404.html')


@app.errorhandler(403)
def forbidden_error(error):
    logging.warning("403 error encountered")
    return template_redirect('403.html')


if __name__ == '__main__':
    with app.app_context():
        logging.info("Creating database tables")
        db.create_all()
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    logging.info(
        f"Starting Flask app in {'debug' if debug_mode else 'production'} mode")
    app.run(debug=debug_mode)

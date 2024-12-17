from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import json
import hashlib
import hmac
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)  # 'google' or 'github'
    provider_id = db.Column(db.String(100), unique=True,
                            nullable=False)  # OAuth unique ID
    name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(100), nullable=True)

# Routes


@app.route('/', methods=['GET', 'POST'])
def home():
    user = session.get('user')
    return render_template('home.html', user=user)


@app.route('/login/<provider>')
def login(provider):
    redirect_uri = url_for('authorize', provider=provider, _external=True)
    return oauth.create_client(provider).authorize_redirect(redirect_uri)


@app.route('/authorize/<provider>')
def authorize(provider):

    if provider == 'telegram':
        return handle_telegram_auth()
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = client.get('user').json()
    return save_user_info(provider, user_info)


@app.route('/telegram_auth', methods=['GET', 'POST'])
def telegram_auth():
    return handle_telegram_auth()

# Function to verify the Telegram auth data


def check_response(data):
    d = data.copy()
    del d['hash']
    d_list = []
    for key in sorted(d.keys()):
        if d[key] is not None:
            d_list.append(f"{key}={d[key]}")
    data_string = '\n'.join(d_list).encode('utf-8')

    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode('utf-8')).digest()
    hmac_string = hmac.new(secret_key, data_string, hashlib.sha256).hexdigest()

    return hmac_string == data['hash']


def handle_telegram_auth():
    data = {
        'id': request.args.get('id'),
        'first_name': request.args.get('first_name'),
        'last_name': request.args.get('last_name'),
        'username': request.args.get('username'),
        'photo_url': request.args.get('photo_url'),
        'auth_date': request.args.get('auth_date'),
        'hash': request.args.get('hash')
    }

    # Check if the response is valid
    if not check_response(data):
        return "Invalid authentication", 403

    # If the response is valid, save the user info
    user_info = {
        'provider': 'telegram',
        'id': data['id'],
        'username': data['username'],
        'first_name': data['first_name'],
        'last_name': data['last_name']
    }

    # Save user info
    return save_user_info('telegram', user_info)


def save_user_info(provider, user_info):
    # Extract key user info
    provider_id = user_info.get('id')
    username = user_info.get(
        'username') if provider == 'telegram' else user_info.get('login')
    name = user_info.get('name') or user_info.get(
        'login')

    # Check if user exists in the database
    user = User.query.filter_by(
        provider=provider, provider_id=provider_id).first()
    if not user:
        # Save new user to the database
        user = User(provider=provider, provider_id=provider_id,
                    username=username, name=name)
        db.session.add(user)
        db.session.commit()

    # Save user to session
    session['user'] = {'name': user.name, 'username': user.username,
                       'provider': user.provider}
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# Initialize the database


initialized = False  # Flag to ensure initialization runs only once


@app.before_request
def init_db_once():
    global initialized
    if not initialized:
        db.create_all()
        initialized = True


if __name__ == '__main__':
    with app.app_context():  # Ensure the app context is available
        db.create_all()      # Create the database tables
    app.run(debug=True)

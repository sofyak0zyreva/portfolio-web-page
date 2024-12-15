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


@app.route('/')
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


@app.route('/telegram_auth', methods=['POST'])
def telegram_auth():
    return handle_telegram_auth()


def handle_telegram_auth():
    data = request.form.to_dict()
    auth_data = data.get('auth_data')
    received_hash = data.get('hash')

    secret_key = TELEGRAM_BOT_TOKEN.encode('utf-8')
    calculated_hash = hmac.new(secret_key, auth_data.encode(
        'utf-8'), hashlib.sha256).hexdigest()

    if calculated_hash != received_hash:
        return "Invalid authentication", 403

    user_info = json.loads(auth_data)
    return save_user_info('telegram', user_info)


def save_user_info(provider, user_info):
    # Extract key user info
    provider_id = user_info.get('id')
    username = user_info.get(
        'username') if provider == 'telegram' else user_info.get('login')
    name = user_info.get('name') or user_info.get(
        'login')  # Fallback to GitHub login if no name

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

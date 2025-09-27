from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.utils import formatdate
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from models import db, User, PasswordResetToken
from forms import LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm
from werkzeug.security import generate_password_hash, check_password_hash
import email_validator
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask_wtf.csrf import generate_csrf
from models import db, User, PasswordResetToken, Item
 
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/door_dash_DB.db'


db_path = os.path.join(os.path.dirname(__file__), 'instance', 'door_dash_DB.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'  # For development
app.config['RATELIMIT_DEFAULT'] = '10 per minute'  # Default rate limit
app.config['RATELIMIT_HEADERS_ENABLED'] = True  # Enable rate limit headers

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# Initialize extensions
csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)
limiter = Limiter(app=app, key_func=get_remote_address)

reset_serializer = URLSafeTimedSerializer(app.secret_key)

# Configure OAuth
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


def send_password_reset_email(to_email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message('Reset Your Password',
                  sender=os.getenv('MAIL_USERNAME'),
                  recipients=[to_email])
    msg.body = f"""Hi 👋,

To reset your password, click the link below:

{reset_link}

If you didn't request this, please ignore this email.

Thanks,
The Kejetia Team,market on the go!

"""
    try:
        mail.send(msg)
    except Exception as e:
        print("[ERROR] Email error:", e)




@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/callback/google')
def google_callback():
    try:
        token = google.authorize_access_token()
        
        # Option 1: Use userinfo endpoint instead of parsing ID token
        resp = google.get('https://www.googleapis.com/oauth2/v2/userinfo', token=token)
        user_info = resp.json()
        
        if user_info:
            email = user_info['email']
            name = user_info.get('name', '')
            
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Create new user with Google account
                # Generate a username from email if name is not available
                username = name if name else email.split('@')[0]
                
                # Ensure username is unique
                counter = 1
                original_username = username
                while User.query.filter_by(username=username).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                user = User(
                    username=username,
                    email=email,
                    is_verified=True
                )
                # Set a random password for OAuth users (they won't use it)
                import secrets
                user.set_password(secrets.token_hex(16))
                
                db.session.add(user)
                db.session.commit()
                
                flash(f'Welcome {name}! Your account has been created.', 'success')
            else:
                flash(f'Welcome back {user.username}!', 'success')
            
            # Log the user in
            session.permanent = True
            session['user_id'] = user.id
            session['ip'] = request.remote_addr
            session['user_agent'] = request.headers.get('User-Agent')
            session['oauth_login'] = True  # Mark as OAuth login
            
            user.update_last_login()
            
            return redirect(url_for('products'))
        else:
            flash('Failed to get user information from Google.', 'danger')
            return redirect(url_for('login'))
            
    except Exception as e:
        app.logger.error(f"Google OAuth error: {str(e)}")
        flash('Authentication failed. Please try again.', 'danger')
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.is_locked():
            flash('Account locked. Try again later.', 'danger')
            return redirect(url_for('login'))

        if user and user.check_password(form.password.data):
            session.permanent = form.remember.data
            session['user_id'] = user.id
            session['ip'] = request.remote_addr
            session['user_agent'] = request.headers.get('User-Agent')
            session['oauth_login'] = False  # Mark as regular login
            user.reset_failed_logins()
            user.update_last_login()
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('products'))
        else:
            if user:
                user.increment_failed_login()
                db.session.commit()
            flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check both username and email uniqueness
        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            if existing_user.username == form.username.data:
                flash('Username already exists!', 'danger')
            else:
                flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        try:
            user = User(
                username=form.username.data,
                email=form.email.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")

    return render_template('register.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)
@app.route('/dashboard/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('dashboard/profile.html', user=user)

@app.route('/dashboard/search')
def search():
    category=request.args.get('category')
    query=request.args.get('query')
    return render_template('dashboard/search.html',query=query,category=category)

@app.route('/dashboard/products')
def products():
    if 'user_id' not in session:
        flash('Please login', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    items = Item.query.all()
    app.logger.info(f'Items:{items}')
    return render_template('dashboard/products.html', user=user, items=items)
@app.route('/dashboard/sell', methods=['GET', 'POST'])
def sell():
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        location = request.form.get('location')
        price = request.form.get('price')  # ✅ Add this line
        video = request.files.get('video')
        photo = request.files.get('photo')

        # Ensure video is provided
        if not video:
            flash('Video is required!', 'danger')
            return redirect(url_for('sell'))

        if not price:
            flash('Price is required!', 'danger')
            return redirect(url_for('sell'))

        try:
            price = float(price)  # ✅ Convert to float, ensure valid type
        except ValueError:
            flash('Price must be a number.', 'danger')
            return redirect(url_for('sell'))

        # Secure filenames
        video_filename = secure_filename(video.filename)
        photo_filename = secure_filename(photo.filename) if photo else None

        os.makedirs('static/uploads/videos', exist_ok=True)
        os.makedirs('static/uploads/photos', exist_ok=True)

        video.save(os.path.join('static/uploads/videos', video_filename))
        if photo:
            photo.save(os.path.join('static/uploads/photos', photo_filename))

        new_item = Item(
            name=name,
            category=category,
            location=location,
            price=price,  # ✅ Add this here
            video_filename=video_filename,
            photo_filename=photo_filename,
            user_id=session.get('user_id')
        )
        db.session.add(new_item)
        db.session.commit()

        flash('Ad posted successfully!', 'success')
        return redirect(url_for('products'))

    csrf_token = generate_csrf()
    return render_template("dashboard/sell.html", user_id=session.get("user_id"), csrf_token=csrf_token)




@app.route('/dashboard/saved')
def saved():
    return render_template('saved.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('home'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = reset_serializer.dumps(user.email, salt='password-reset')
            reset_token = PasswordResetToken(
                user_id=user.id,
                token_hash=generate_password_hash(token),
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            db.session.add(reset_token)
            db.session.commit()
            send_password_reset_email(user.email, token)

            return render_template('forgot_password_sent.html', email=user.email)
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', form=form)



# Add this before your routes
@app.template_filter('regex_search_filter')  # Exact name used in template
def regex_search_filter(s, pattern):
    import re
    return bool(re.search(pattern, s)) if s else False


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = reset_serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        reset_token = PasswordResetToken.query.filter_by(user_id=user.id).order_by(
            PasswordResetToken.expires_at.desc()).first()
        if not reset_token or not check_password_hash(reset_token.token_hash, token):
            flash('Invalid reset token.', 'danger')
            return redirect(url_for('login'))

        if reset_token.expires_at < datetime.utcnow():
            flash('Reset link has expired.', 'danger')
            return redirect(url_for('login'))

        user.set_password(form.password.data)
        reset_token.is_used = True
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
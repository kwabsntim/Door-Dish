from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher, exceptions
from datetime import datetime
db = SQLAlchemy()
ph = PasswordHasher()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password, password)
        except exceptions.VerifyMismatchError:
            return False

    def increment_failed_login(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()


    def reset_failed_logins(self):
        self.failed_attempts = 0
        self.locked_until = None
        db.session.commit()

    def is_locked(self):
        return self.locked_until and datetime.utcnow() < self.locked_until

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(200), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_valid(self):
        return not self.is_used and datetime.utcnow() < self.expires_at
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  
    category = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False )
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(120), nullable=False)
    photo_filename = db.Column(db.String(255))
    video_filename = db.Column(db.String(255), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    Phone_number = db.Column(db.String(15), nullable=False)


    user = db.relationship('User', backref='items')  # 👈 Allows item.user and user.items

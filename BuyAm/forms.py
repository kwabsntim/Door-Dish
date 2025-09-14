from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField  # Added BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')  # Add this line
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20),
        Regexp('^[A-Za-z0-9_]+$', message='Only letters, numbers and underscores')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
    DataRequired(),
    Length(min=4, max=30),  # Allows 4 to 12 characters
    Regexp(r'^[A-Za-z\d@$!#%*?&]{4,30}$',  # Allows letters, numbers, special chars
           message="Password can contain letters, numbers, and @$!#%*?&")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
    DataRequired(),
    EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Register')



class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=12),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%#*?&])[A-Za-z\d@$!%*#?&]{12,}$')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password')
    ])
    submit = SubmitField('Reset Password')

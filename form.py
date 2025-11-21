from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, BooleanField,
    HiddenField, SelectField, TextAreaField, RadioField
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length,
    ValidationError, Regexp, Optional
)
import re
from datetime import datetime, timedelta
import bleach
from flask import request, current_app
from werkzeug.security import check_password_hash
import json

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=4, max=20, message='Username must be 4-20 characters'),
        Regexp(r'^[a-zA-Z0-9_]+$', 
               message='Only letters, numbers and underscores allowed')
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email format'),
        Length(max=120, message='Email too long')
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password required'),
        Length(min=12, message='Minimum 12 characters'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',
               message='Must include uppercase, lowercase, number and special character')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm password'),
        EqualTo('password', message='Passwords must match')
    ])
    
    terms = BooleanField('I accept the Terms and Privacy Policy', validators=[
        DataRequired(message='You must accept terms')
    ])
    
    theme_preference = SelectField('Theme', choices=[
        ('system', 'System Default'),
        ('light', 'Light Mode'),
        ('dark', 'Dark Mode')
    ], default='system')
    
    submit = SubmitField('Register')

    def validate_username(self, field):
        sanitized = bleach.clean(field.data, strip=True)
        if sanitized != field.data:
            raise ValidationError('Invalid characters in username')
            
        reserved = ['admin', 'root', 'system', 'moderator', 'support']
        if field.data.lower() in reserved:
            raise ValidationError('This username is reserved')
            
        from .models import User
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

    def validate_email(self, field):
        sanitized = bleach.clean(field.data, strip=True)
        if sanitized != field.data:
            raise ValidationError('Invalid characters in email')
            
        if self.is_disposable_email(field.data):
            raise ValidationError('Disposable emails not allowed')
            
        from .models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_password(self, field):
        if self.is_breached_password(field.data):
            raise ValidationError('This password was found in data breaches')
            
        if (hasattr(self, 'username') and 
            self.username.data.lower() in field.data.lower()):
            raise ValidationError('Password cannot contain username')

    @staticmethod
    def is_disposable_email(email):
        """Check if email is from a disposable provider"""
        disposable_domains = [
            'tempmail', 'mailinator', '10minutemail', 'guerrillamail',
            'throwaway', 'fake', 'trashmail', 'dispostable'
        ]
        domain = email.split('@')[-1].lower()
        return any(d in domain for d in disposable_domains)

    @staticmethod
    def is_breached_password(password):
        """Simple check against common breached passwords"""
        common_passwords = [
            'password', '123456', 'qwerty', 'letmein', 'welcome',
            'admin123', 'password1', 'abc123', '111111'
        ]
        return password.lower() in common_passwords


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Email required'),
        Email(message='Invalid email format')
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password required')
    ])
    
    remember = BooleanField('Remember me')
    submit = SubmitField('Log In')

    def validate_email(self, field):
        from .models import User
        user = User.query.filter_by(email=field.data).first()
        if not user:
            raise ValidationError('No account found with this email')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Email required'),
        Email(message='Invalid email format')
    ])
    
    submit = SubmitField('Request Reset')

    def validate_email(self, field):
        from .models import User
        user = User.query.filter_by(email=field.data).first()
        if not user:
            raise ValidationError('No account with this email exists')
            
        if (user.last_activity and 
            (datetime.utcnow() - user.last_activity) < timedelta(minutes=5)):
            raise ValidationError('Reset already requested. Wait 5 minutes.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(message='Password required'),
        Length(min=12, message='Minimum 12 characters'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',
               message='Must include uppercase, lowercase, number and special character')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm password'),
        EqualTo('password', message='Passwords must match')
    ])
    
    submit = SubmitField('Reset Password')

    def validate_password(self, field):
        if RegistrationForm.is_breached_password(field.data):
            raise ValidationError('This password was found in data breaches')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Current password required')
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='New password required'),
        Length(min=12, message='Minimum 12 characters'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',
               message='Must include uppercase, lowercase, number and special character')
    ])
    
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm new password'),
        EqualTo('new_password', message='Passwords must match')
    ])
    
    submit = SubmitField('Change Password')

    def validate_new_password(self, field):
        if field.data == self.current_password.data:
            raise ValidationError('New password must be different')
            
        if RegistrationForm.is_breached_password(field.data):
            raise ValidationError('This password was found in data breaches')


class TwoFactorForm(FlaskForm):
    code = StringField('Verification Code', validators=[
        DataRequired(message='Code required'),
        Length(min=6, max=6, message='Must be 6 digits'),
        Regexp(r'^\d{6}$', message='Must be numeric')
    ])
    
    submit = SubmitField('Verify')


class UpdateEmailForm(FlaskForm):
    email = StringField('New Email', validators=[
        DataRequired(message='Email required'),
        Email(message='Invalid email format'),
        Length(max=120, message='Email too long')
    ])
    
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Password required')
    ])
    
    submit = SubmitField('Update Email')

    def validate_email(self, field):
        if RegistrationForm.is_disposable_email(field.data):
            raise ValidationError('Disposable emails not allowed')
            
        from .models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')


class QuizForm(FlaskForm):
    """Form for quiz submissions with CSRF protection"""
    csrf_token = HiddenField('CSRF Token')
    tutorial_num = HiddenField('Tutorial Number', validators=[DataRequired()])
    answers = HiddenField('Answers')  # Will store JSON of answers
    submit = SubmitField('Submit Quiz')


class ProfileForm(FlaskForm):
    bio = TextAreaField('Bio', validators=[
        Length(max=500, message='Bio cannot exceed 500 characters'),
        Optional()
    ])
    
    location = StringField('Location', validators=[
        Length(max=100, message='Location too long'),
        Optional()
    ])
    
    theme_preference = SelectField('Theme', choices=[
        ('system', 'System Default'),
        ('light', 'Light Mode'),
        ('dark', 'Dark Mode')
    ], default='system')
    
    submit = SubmitField('Update Profile')

    def validate_bio(self, field):
        if field.data:
            sanitized = bleach.clean(field.data, strip=True)
            if sanitized != field.data:
                raise ValidationError('Bio contains invalid characters')


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(message='Name required'),
        Length(max=100, message='Name too long')
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message='Email required'),
        Email(message='Invalid email format'),
        Length(max=120, message='Email too long')
    ])
    
    message = TextAreaField('Message', validators=[
        DataRequired(message='Message required'),
        Length(max=1000, message='Message too long')
    ])
    
    submit = SubmitField('Send Message')

    def validate_message(self, field):
        sanitized = bleach.clean(field.data, strip=True)
        if sanitized != field.data:
            raise ValidationError('Message contains invalid characters')


class TutorialSelectionForm(FlaskForm):
    tutorial = SelectField('Select Tutorial', coerce=int, validators=[
        DataRequired(message='Please select a tutorial')
    ])
    
    submit = SubmitField('Start Tutorial')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import Tutorial
        self.tutorial.choices = [(t.id, t.title) for t in Tutorial.query.order_by(Tutorial.id).all()]


class QuizAnswerForm(FlaskForm):
    """Dynamic form for quiz answers"""
    def __init__(self, questions, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.questions = questions
        for i, question in enumerate(questions):
            if question['type'] == 'true_false':
                self[f'q{i}'] = RadioField(
                    question['question'],
                    choices=[('True', 'True'), ('False', 'False')],
                    validators=[DataRequired()]
                )
            else:
                self[f'q{i}'] = RadioField(
                    question['question'],
                    choices=[(opt, opt) for opt in question['options']],
                    validators=[DataRequired()]
                )
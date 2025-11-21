# Suppress Flask-Admin pkg_resources Warning (Temporary)
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="flask_admin.contrib")

# Standard & Third-party Imports
import os
import sys
import re
import json
import secrets
import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, urljoin
from collections import defaultdict, namedtuple

import pytz
import requests
import bleach
import bcrypt
import pyotp
import geoip2.database
from dotenv import load_dotenv
from email_validator import validate_email
from user_agents import parse as parse_ua

# Flask Core
from flask import (
    Flask, request, session, render_template, redirect, url_for, jsonify,
    flash, abort, current_app, make_response, send_from_directory, Response, g
)
from werkzeug.exceptions import HTTPException, BadRequest, NotFound, Forbidden, Unauthorized
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Flask Extensions
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import (
    LoginManager, UserMixin, current_user, login_user, logout_user,
    login_required, fresh_login_required
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_caching import Cache
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf

# WTForms
from wtforms import (
    StringField, PasswordField, SubmitField, BooleanField, TextAreaField,
    SelectField, HiddenField, FileField, RadioField
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Optional, ValidationError, Regexp
)
from wtforms.widgets import PasswordInput

# SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, func, select, and_, or_, desc, asc,
    event, inspect, exists, update, Index, text, union_all, case, cast, between, StaticPool
)
from sqlalchemy.exc import (
    IntegrityError, NoResultFound, OperationalError, SQLAlchemyError, MultipleResultsFound
)
from sqlalchemy.orm import (
    relationship, backref, sessionmaker, scoped_session, joinedload,
    validates, aliased, deferred, Session, column_property, subqueryload
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PG_UUID
from sqlalchemy.sql.expression import label, literal

# Security & Crypto
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

app = Flask(__name__)

# Load environment variables from .env
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

# FIXED: Ensure database directory exists and use absolute path
database_path = os.path.join(basedir, 'click_aware.db')
database_dir = os.path.dirname(database_path)
if not os.path.exists(database_dir):
    os.makedirs(database_dir, exist_ok=True)

database_uri = os.getenv('DATABASE_URL', f'sqlite:///{database_path}')

# Primary application configuration
app.config.update(
    APPLICATION_ROOT='/',
    SERVER_NAME=os.getenv('SERVER_NAME', None),
    SUPPORT_EMAIL=os.getenv('SUPPORT_EMAIL', 'support@yourdomain.com'),

    DEBUG=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
    TESTING=False,
    ENV=os.getenv('FLASK_ENV', 'production'),

    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_urlsafe(64)),
    PROPAGATE_EXCEPTIONS=True,

    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.getenv('CSRF_SECRET_KEY', secrets.token_urlsafe(32)),
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_SSL_STRICT=False,  # Relaxed for development
    WTF_CSRF_CHECK_DEFAULT=True,
    WTF_CSRF_METHODS=['POST', 'PUT', 'PATCH', 'DELETE'],
    WTF_CSRF_FIELD_NAME='csrf_token',

    SESSION_COOKIE_SECURE=False,  # Set to True in production
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='sessionid',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True,

    REMEMBER_COOKIE_SECURE=False,  # Set to True in production
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_NAME='remember_token',
    REMEMBER_COOKIE_DURATION=timedelta(days=30),

    SQLALCHEMY_DATABASE_URI=database_uri,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_RECORD_QUERIES=app.debug,

    JSON_AS_ASCII=False,
    JSONIFY_PRETTYPRINT_REGULAR=False,
    JSONIFY_MIMETYPE='application/json',
    JSON_SORT_KEYS=False,
    SEND_FILE_MAX_AGE_DEFAULT=timedelta(seconds=3600),
    STATIC_FOLDER=os.path.join(basedir, 'static'),
    TEMPLATES_AUTO_RELOAD=True,  # Enable for development
    TEMPLATES_AUTO_ESCAPE=True,

    FLASK_ADMIN_SWATCH='cerulean',
    FLASK_ADMIN_FLUID_LAYOUT=True,

    PREFERRED_URL_SCHEME='https',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,

    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.yourdomain.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com'),

    CACHE_TYPE='SimpleCache',  # Simplified for development
    CACHE_DEFAULT_TIMEOUT=300,

    RATELIMIT_STORAGE_URI='memory://',  # Use memory for development
    RATELIMIT_STRATEGY='fixed-window',

    PROMETHEUS_ENABLED=os.getenv('PROMETHEUS_ENABLED', 'false').lower() == 'true',
    FEATURE_2FA_ENABLED=os.getenv('FEATURE_2FA_ENABLED', 'true').lower() == 'true',
    FEATURE_API_ENABLED=os.getenv('FEATURE_API_ENABLED', 'true').lower() == 'true'
)

# Database engine config
engine_options = {'pool_pre_ping': True, 'pool_recycle': 3600}

if database_uri.startswith('postgresql'):
    engine_options.update({'pool_timeout': 10, 'pool_recycle': 300})
elif database_uri.startswith('sqlite'):
    engine_options.update({
        'connect_args': {'check_same_thread': False, 'timeout': 30},
        'poolclass': StaticPool
    })
elif database_uri.startswith('mysql'):
    engine_options.update({'pool_timeout': 30, 'max_overflow': 20, 'pool_size': 10})

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)
cache = Cache(app)
login_manager = LoginManager(app)
limiter = Limiter(
    app=app, 
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

# Talisman for security headers (disabled in development for easier testing)
talisman = Talisman(
    app,
    content_security_policy=None,  # Disable for development
    force_https=False,  # Disable for development
    session_cookie_secure=False
)

# Login Manager configuration
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = "basic"  # Changed to basic for development
login_manager.refresh_view = "login"
login_manager.needs_refresh_message = "For security reasons, please reauthenticate to access this page."
login_manager.needs_refresh_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError, SQLAlchemyError) as e:
        current_app.logger.error(f"User loading error: {str(e)}", exc_info=True)
        return None

@app.context_processor
def inject_global_vars():
    try:
        current_user_data = {
            'is_authenticated': current_user.is_authenticated,
            'username': getattr(current_user, 'username', None),
            'streak': getattr(current_user, 'streak', 0),
        }
    except Exception:
        current_user_data = {}

    return {
        'csrf_token': generate_csrf,
        'is_secure': request.is_secure,
        'current_year': datetime.now().year,
        'app_config': {
            'name': os.getenv('APP_NAME', 'Clickaware'),
            'version': os.getenv('APP_VERSION', '1.0.0'),
            'env': os.getenv('FLASK_ENV', 'production'),
        },
        'user_models': {
            'User': User,
            'Detection': Detection,
            'QuizResult': QuizResult,
            'UserProgress': UserProgress,
        },
        'feature_flags': {
            '2fa_enabled': app.config.get('FEATURE_2FA_ENABLED', False),
            'api_enabled': app.config.get('FEATURE_API_ENABLED', False),
        },
        'current_user_data': current_user_data
    }

# MODELS
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    streak = db.Column(db.Integer, default=0)
    streak_freezes = db.Column(db.Integer, default=0)
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    badges = db.Column(db.String(500), default='[]')
    quiz_results = db.relationship('QuizResult', backref='user', lazy=True, cascade="all, delete-orphan")
    detections = db.relationship('Detection', backref='user', lazy=True, cascade="all, delete-orphan")
    progress = db.relationship('UserProgress', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters')
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def add_badge(self, badge_name):
        """Adds a badge to the user if not already earned"""
        try:
            badges = json.loads(self.badges) if self.badges else []
            if not isinstance(badges, list):  # Handle corrupted badge data
                badges = []
            if badge_name not in badges:
                badges.append(badge_name)
                self.badges = json.dumps(badges)
                return True
            return False
        except json.JSONDecodeError:
            self.badges = json.dumps([badge_name])
            return True

    def get_badges(self):
        """Returns the user's badges as a list"""
        try:
            return json.loads(self.badges) if self.badges else []
        except json.JSONDecodeError:
            return []

    def update_streak(self):
        """Updates the user's streak based on last activity"""
        now = datetime.now(timezone.utc)
        if self.last_activity:
            # Reset streak if more than 2 days since last activity
            if (now - self.last_activity).days > 1:
                if self.streak_freezes > 0:
                    self.streak_freezes -= 1
                else:
                    self.streak = 0
        self.last_activity = now
        if self.streak == 0 or (now - self.last_activity).days == 1:
            self.streak += 1

class Detection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    referrer = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tutorial_num = db.Column(db.Integer)
    score = db.Column(db.Float)
    passed = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    answer_details = db.Column(db.Text)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    concept = db.Column(db.String(100))
    mastery = db.Column(db.Float, default=0)
    next_review = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    attempts = db.Column(db.Integer, default=0)
    correct = db.Column(db.Integer, default=0)
    interval = db.Column(db.Integer, default=1)  # Added missing field

class Tutorial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(1000), nullable=False)
    resources = db.Column(db.Text, nullable=False)  # JSON list of resource keys

    def get_resources(self):
        try:
            return json.loads(self.resources)
        except Exception:
            return []

# ======== FLASK-ADMIN ========
class UserModelView(ModelView):
    can_export = True
    export_types = ['csv', 'json']
    column_list = ['username', 'email', 'is_admin', 'streak', 'last_activity']
    column_default_sort = ('last_activity', True)
    column_searchable_list = ['username', 'email']
    column_filters = ['is_admin']
    column_editable_list = ['is_admin']

    form_columns = ['username', 'email', 'password', 'is_admin', 'streak', 'badges']
    form_extra_fields = {
        'password': PasswordField(
            'New Password',
            description='Leave blank to keep current password',
            validators=[Optional(), Length(min=8)]
        )
    }

    form_args = {
        'username': {
            'label': 'Username',
            'validators': [
                DataRequired(),
                Length(min=4, max=80),
                Regexp('^[A-Za-z0-9_]+$', message='Only letters, numbers and underscores allowed')
            ]
        },
        'email': {
            'label': 'Email',
            'validators': [
                DataRequired(),
                Email(),
                Length(max=120)
            ]
        }
    }

    form_widget_args = {
        'password_hash': {
            'readonly': True,
            'class': 'form-control-plaintext'
        },
        'badges': {
            'rows': 3,
            'style': 'font-family: monospace;'
        }
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        flash('You need admin privileges to access this page', 'danger')
        return redirect(url_for('dashboard'))

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            if len(form.password.data) < 8:
                raise ValueError('Password must be at least 8 characters')
            model.set_password(form.password.data)
        return super().on_model_change(form, model, is_created)

class MyAdminIndex(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))

        # Calculate counts
        user_count = db.session.query(User).count()
        detection_count = db.session.query(Detection).count()
        quizresult_count = db.session.query(QuizResult).count()
        tutorial_count = db.session.query(Tutorial).count()

        # Load slideshow images from static/img folder
        images = []
        try:
            image_dir = os.path.join(app.static_folder, 'img')
            if os.path.isdir(image_dir):
                images = [
                    f for f in os.listdir(image_dir)
                    if os.path.isfile(os.path.join(image_dir, f)) and
                    f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))
                ]
        except Exception as e:
            app.logger.error(f"Error loading admin images: {str(e)}")

        return self.render(
            'admin/index.html',
            images=images,
            user_count=user_count,
            detection_count=detection_count,
            quizresult_count=quizresult_count,
            tutorial_count=tutorial_count
        )

# Initialize Flask-Admin
admin = Admin(
    app,
    name='Cyber Admin',
    template_mode='bootstrap3',
    index_view=MyAdminIndex(
        url='/admin',
        endpoint='admin'
    )
)

# Register views
admin.add_view(UserModelView(User, db.session, name='Users', category='User Management'))
admin.add_view(ModelView(Detection, db.session, name='Detections', category='Data'))
admin.add_view(ModelView(QuizResult, db.session, name='Quiz Results', category='Data'))
admin.add_view(ModelView(UserProgress, db.session, name='User Progress', category='Data'))
admin.add_view(ModelView(Tutorial, db.session, name='Tutorials', category='Content Management'))

# ======== KNOWLEDGE BASE ========
SAFETY_RESOURCES = {
    # Phishing Resources (3)
    "FTC Phishing Guide": {
        "url": "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
        "key_points": [
            "Phishing scams impersonate trusted organizations",
            "Never provide personal info via pop-up ads",
            "Legitimate companies won't ask for passwords via email",
            "Hover over links to verify destinations",
            "Report phishing attempts to the FTC"
        ],
        "category": "phishing"
    },
    "CISA Phishing Tips": {
        "url": "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-scams",
        "key_points": [
            "Verify unexpected requests via official channels",
            "Don't trust caller ID information",
            "Be wary of urgent/emotional language",
            "Check for HTTPS and valid certificates",
            "Use multi-factor authentication"
        ],
        "category": "phishing"
    },
    "APWG Phishing Trends": {
        "url": "https://apwg.org/trendsreports/",
        "key_points": [
            "Mobile phishing attacks increased 50% last year",
            "SMS phishing (smishing) is growing rapidly",
            "Brand impersonation most common tactic",
            "Financial institutions most targeted",
            "Friday afternoons see most phishing attempts"
        ],
        "category": "phishing"
    },

    # Malvertising Resources (3)
    "Malwarebytes Malvertising": {
        "url": "https://www.malwarebytes.com/malvertising",
        "key_points": [
            "Malvertising injects malicious code into ads",
            "Even reputable sites can serve compromised ads",
            "Ad blockers prevent most malvertising",
            "Flash Player was a common infection vector",
            "Can lead to ransomware infections"
        ],
        "category": "malvertising"
    },
    "EFF Ad Blocking": {
        "url": "https://www.eff.org/pages/tracker-protection",
        "key_points": [
            "Ad blockers improve privacy and security",
            "Blocks tracking scripts and malicious ads",
            "uBlock Origin recommended for best protection",
            "Consider Privacy Badger for additional tracking protection",
            "Regularly update your ad blocker filters"
        ],
        "category": "malvertising"
    },
    "IAB Malvertising Guide": {
        "url": "https://www.iab.com/guidelines/malvertising/",
        "key_points": [
            "Publishers should vet ad networks carefully",
            "Use secure ad serving (HTTPS only)",
            "Implement click fraud detection",
            "Sandbox iframe ads for isolation",
            "Monitor for suspicious redirects"
        ],
        "category": "malvertising"
    },

    # Browser Security (3)
    "Chrome Security Features": {
        "url": "https://www.google.com/chrome/security/",
        "key_points": [
            "Safe Browsing warns about dangerous sites",
            "Automatic updates patch vulnerabilities",
            "Sandboxing isolates tabs from each other",
            "Site Isolation protects against Spectre attacks",
            "Password Checkup alerts about compromised credentials"
        ],
        "category": "browser_security"
    },
    "Firefox Privacy Guide": {
        "url": "https://support.mozilla.org/en-US/kb/firefox-privacy-and-security-features",
        "key_points": [
            "Enhanced Tracking Protection blocks trackers",
            "DNS-over-HTTPS encrypts domain lookups",
            "Facebook Container isolates Facebook activity",
            "Built-in password manager with sync",
            "Automatic blocking of cryptominers"
        ],
        "category": "browser_security"
    },
    "Safari Security Overview": {
        "url": "https://support.apple.com/guide/safari/prevent-cross-site-tracking-sfri40732/mac",
        "key_points": [
            "Intelligent Tracking Prevention blocks trackers",
            "Fingerprinting protection makes devices harder to identify",
            "Warns about weak passwords",
            "Private Relay encrypts browsing activity",
            "Automatic blocking of malicious sites"
        ],
        "category": "browser_security"
    },

    # Password Security (2)
    "NIST Password Guidelines": {
        "url": "https://pages.nist.gov/800-63-3/sp800-63b.html",
        "key_points": [
            "Use long, memorable passphrases (not complex passwords)",
            "Enable multi-factor authentication everywhere",
            "Password managers are recommended",
            "No more frequent forced password changes",
            "Check against breach databases"
        ],
        "category": "passwords"
    },
    "HaveIBeenPwned Guide": {
        "url": "https://haveibeenpwned.com/",
        "key_points": [
            "Check if your accounts appear in breaches",
            "Use unique passwords for every site",
            "Enable 2FA wherever available",
            "Monitor for new breaches regularly",
            "Consider using password manager-generated passwords"
        ],
        "category": "passwords"
    },

    # Social Engineering (3)
    "KnowBe4 Social Engineering": {
        "url": "https://www.knowbe4.com/social-engineering",
        "key_points": [
            "80% of security incidents start with social engineering",
            "Common tactics: urgency, authority, scarcity",
            "Verify unusual requests through known channels",
            "Never share credentials over phone/email",
            "Train staff to recognize red flags"
        ],
        "category": "social_engineering"
    },
    "Microsoft Tech Support Scams": {
        "url": "https://www.microsoft.com/en-us/security/business/security-101/how-to-spot-tech-support-scams",
        "key_points": [
            "Microsoft never makes unsolicited support calls",
            "Scammers use fake error messages to create urgency",
            "Never grant remote access to unknown parties",
            "Legitimate companies won't demand payment in gift cards",
            "Report scams to the FTC"
        ],
        "category": "social_engineering"
    },
    "FTC Impersonation Scams": {
        "url": "https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
        "key_points": [
            "Scammers impersonate government agencies",
            "They threaten legal action or fines",
            "Real agencies never demand immediate payment",
            "Never pay with cryptocurrency or gift cards",
            "Verify by contacting the real agency directly"
        ],
        "category": "social_engineering"
    },

    # Mobile Security (2)
    "Google Mobile Security": {
        "url": "https://www.android.com/security-center/",
        "key_points": [
            "Only install apps from Google Play Store",
            "Keep device OS updated",
            "Review app permissions regularly",
            "Use Find My Device for lost phones",
            "Enable Google Play Protect scanning"
        ],
        "category": "mobile"
    },
    "Apple iOS Security": {
        "url": "https://support.apple.com/guide/security/welcome/web",
        "key_points": [
            "App Store review prevents most malware",
            "Automatic security updates install overnight",
            "Face ID/Touch ID more secure than passwords",
            "iMessage encryption protects communications",
            "Lockdown Mode for extreme protection"
        ],
        "category": "mobile"
    },

    # Network Security (2)
    "CISA Home Network Security": {
        "url": "https://www.cisa.gov/securing-home-network",
        "key_points": [
            "Change default router admin credentials",
            "Enable WPA3 encryption on WiFi",
            "Create guest network for visitors",
            "Disable WPS (WiFi Protected Setup)",
            "Keep router firmware updated"
        ],
        "category": "networking"
    },
    "EFF Surveillance Self-Defense": {
        "url": "https://ssd.eff.org/",
        "key_points": [
            "Use VPNs on public WiFi",
            "Prefer encrypted messaging apps",
            "HTTPS Everywhere encrypts web connections",
            "Tor Browser provides anonymous browsing",
            "Encrypt sensitive device storage"
        ],
        "category": "networking"
    },

    # Additional Resources (2)
    "NIST Ransomware Guide": {
        "url": "https://www.nist.gov/itl/smallbusinesscyber/guidelines-topic-ransomware",
        "key_points": [
            "Maintain offline backups of critical data",
            "Don't pay ransoms - no guarantee of recovery",
            "Patch systems promptly",
            "Use application allowlisting",
            "Train staff to recognize phishing attempts"
        ],
        "category": "ransomware"
    },
    "CISA Zero Trust": {
        "url": "https://www.cisa.gov/zero-trust",
        "key_points": [
            "Verify explicitly - never trust, always verify",
            "Least privilege access only",
            "Assume breach - segment networks accordingly",
            "Multi-factor authentication everywhere",
            "Continuous monitoring and validation"
        ],
        "category": "advanced"
    }
}

TUTORIALS = {
    1: {
        "url": "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-scams",
        "resources": ["FTC Phishing Guide", "CISA Phishing Tips"],
        "title": "Phishing Awareness"
    },
    2: {
        "url": "https://us-cert.cisa.gov/ncas/tips/ST18-001",
        "resources": ["Malwarebytes Malvertising", "EFF Ad Blocking"],
        "title": "Malware Protection"
    },
    3: {
        "url": "https://staysafeonline.org/stay-safe-online/",
        "resources": ["Chrome Security Features", "Firefox Privacy Guide"],
        "title": "Online Safety"
    },
    4: {
        "url": "https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
        "resources": ["APWG Phishing Trends", "KnowBe4 Social Engineering"],
        "title": "Advanced Phishing"
    },
    5: {
        "url": "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
        "resources": ["NIST Password Guidelines", "HaveIBeenPwned Guide"],
        "title": "Password Security"
    },
    6: {
        "url": "https://www.cisa.gov/news-events/news/implementing-strong-authentication",
        "resources": ["Google Mobile Security", "Apple iOS Security"],
        "title": "Mobile Security"
    },
    7: {
        "url": "https://www.imperva.com/learn/application-security/social-engineering/",
        "resources": ["Microsoft Tech Support Scams", "FTC Impersonation Scams"],
        "title": "Social Engineering"
    },
    8: {
        "url": "https://us.norton.com/blog/emerging-threats/how-to-identify-and-avoid-phishing-scams",
        "resources": ["CISA Home Network Security", "EFF Surveillance Self-Defense"],
        "title": "Network Security"
    },
    9: {
        "url": "https://www.kaspersky.com/resource-center/preemptive-safety/mobile-device-security",
        "resources": ["NIST Ransomware Guide"],
        "title": "Advanced Threats"
    },
    10: {
        "url": "https://www.cisa.gov/report",
        "resources": ["CISA Zero Trust"],
        "title": "Reporting Incidents"
    }
}

READING_SUMMARY = {
    1: "Learn to identify and avoid phishing attempts that try to steal your credentials.",
    2: "Understand different types of malware and how they compromise your system.",
    3: "Discover safe internet practices to protect your online activity.",
    4: "Explore how malicious ads work and how to avoid clicking them.",
    5: "Learn the importance of strong and unique passwords.",
    6: "Understand how two-factor authentication adds a layer of protection.",
    7: "Uncover the techniques social engineers use to manipulate users.",
    8: "Identify common traits of fraudulent email scams.",
    9: "Learn how to secure your smartphone and avoid threats.",
    10: "Understand the correct procedure to report a cybersecurity incident."
}

class QuizEngine:
    def __init__(self):
        self.question_bank = self._build_question_bank()
        self.explanations = self._build_explanations()

    def _build_question_bank(self):
        bank = defaultdict(list)
        
        for tutorial_num, tutorial_data in TUTORIALS.items():
            if tutorial_num > 10:  # Only use first 10 tutorials for quizzes
                continue

            for resource_name in tutorial_data.get("resources", []):
                resource = SAFETY_RESOURCES[resource_name]
                category = resource["category"]

                # Multiple choice questions
                for concept in resource["key_points"]:
                    bank[tutorial_num].append({
                        "type": "multiple_choice",
                        "question": f"Which of these best describes: '{concept.split(':')[0]}'?",
                        "options": self._generate_options(concept, resource_name),
                        "answer": concept,
                        "difficulty": 1,
                        "resource": resource_name,
                        "explanation": self._get_explanation(concept, resource_name)
                    })

                # True/False questions with more precise answers
                for concept in resource["key_points"][:3]:
                    # Make some statements false for better learning
                    make_false = random.choice([True, False])
                    if make_false:
                        false_concept = self._generate_false_statement(concept, category)
                        bank[tutorial_num].append({
                            "type": "true_false",
                            "question": f"True or False: {false_concept}",
                            "options": ["True", "False"],
                            "answer": "False",
                            "difficulty": 1,
                            "resource": resource_name,
                            "explanation": f"This is false because: {concept}"
                        })
                    else:
                        bank[tutorial_num].append({
                            "type": "true_false",
                            "question": f"True or False: {concept}",
                            "options": ["True", "False"],
                            "answer": "True",
                            "difficulty": 1,
                            "resource": resource_name,
                            "explanation": f"This is true as explained in: {resource_name}"
                        })

                # Scenario-based questions
                scenarios = self._generate_scenarios(category)
                for scenario in scenarios:
                    correct_answer = "Report to IT/security team" if "report" in scenario.lower() else "Verify through official channels"
                    bank[tutorial_num].append({
                        "type": "scenario",
                        "question": f"What should you do in this situation: {scenario}?",
                        "options": [
                            "Ignore it and continue browsing",
                            "Verify through official channels",
                            "Click to investigate further",
                            "Report to IT/security team"
                        ],
                        "answer": correct_answer,
                        "difficulty": 2,
                        "resource": resource_name,
                        "explanation": self._get_scenario_explanation(scenario, correct_answer)
                    })

        return bank

    def _build_explanations(self):
        """Build a dictionary of explanations for concepts"""
        explanations = {}
        for resource in SAFETY_RESOURCES.values():
            for concept in resource["key_points"]:
                explanations[concept] = {
                    "detail": concept,
                    "resource": resource["url"],
                    "category": resource["category"]
                }
        return explanations

    def _get_explanation(self, concept, resource_name):
        """Get explanation for a concept"""
        resource = SAFETY_RESOURCES[resource_name]
        return {
            "text": f"This concept is explained in {resource_name}",
            "link": resource["url"],
            "key_points": resource["key_points"]
        }

    def _get_scenario_explanation(self, scenario, correct_answer):
        """Generate explanation for scenario questions"""
        if "report" in correct_answer.lower():
            return "You should always report suspicious activities to security teams as they may indicate broader threats."
        return "When in doubt, always verify through official channels rather than interacting with potentially malicious content."

    def _generate_false_statement(self, true_concept, category):
        """Generate plausible false statements for true/false questions"""
        false_statements = {
            "phishing": [
                f"It's safe to click links in emails from your bank",
                f"Legitimate companies often ask for passwords via email",
                f"You don't need to verify SSL certificates on banking sites"
            ],
            "malvertising": [
                f"Ads from reputable sites are always safe to click",
                f"Browser popups about virus infections are always legitimate",
                f"Free software downloads from ads are safe if they look professional"
            ],
            "browser_security": [
                f"It's safe to ignore browser security warnings",
                f"All browser extensions are thoroughly vetted for security",
                f"You should always accept notifications from websites"
            ]
        }
        return random.choice(false_statements.get(category, [
            f"This statement is false: {true_concept}",
            f"Contrary to security best practices: {true_concept}"
        ]))

    def _generate_options(self, correct_answer, resource_name, num_options=4):
        options = [correct_answer]
        while len(options) < num_options:
            # Get random key points from other resources in same category
            category = SAFETY_RESOURCES[resource_name]["category"]
            similar_resources = [r for r in SAFETY_RESOURCES.values() if r["category"] == category]
            if similar_resources:
                random_resource = random.choice(similar_resources)
                random_point = random.choice(random_resource['key_points'])
                if random_point not in options:
                    options.append(random_point)
            else:
                # Fallback to any random point if no same-category resources
                random_resource = random.choice(list(SAFETY_RESOURCES.values()))
                random_point = random.choice(random_resource['key_points'])
                if random_point not in options:
                    options.append(random_point)
        random.shuffle(options)
        return options

    def _generate_scenarios(self, category):
        scenarios = {
            "phishing": [
                "You receive an email from your bank asking you to verify your account details",
                "A popup appears claiming your computer is infected with a virus",
                "You get a text message offering a free gift card for completing a survey",
                "An email claims you need to update your payment information for a service you use"
            ],
            "malvertising": [
                "You see an ad offering a free software download you've been looking for",
                "A banner ad looks exactly like a system alert on your computer",
                "A popup claims you've won a prize in a contest you don't remember entering",
                "An ad redirects you to a page asking for personal information"
            ],
            "browser_security": [
                "Your browser warns you a site's security certificate is invalid",
                "You're asked to install a browser extension to view content",
                "A website asks for permission to show notifications",
                "You receive a prompt to update your browser from an unfamiliar site"
            ]
        }
        return scenarios.get(category, [])

    def get_questions(self, tutorial_num, num=10):
        if tutorial_num not in self.question_bank:
            return []
        available_questions = self.question_bank[tutorial_num]
        return random.sample(available_questions, min(num, len(available_questions)))

# Initialize quiz engine after all models are defined
quiz_engine = QuizEngine()

# Helper Functions
def get_random_security_tip():
    tips = [
        {"text": "Ad-blockers prevent 92% of malvertising attacks", "icon": "fa-shield-virus"},
        {"text": "80% of phishing starts with legitimate-looking ads", "icon": "fa-fish"},
        {"text": "Hover over links to see actual destinations", "icon": "fa-mouse-pointer"}
    ]
    return random.choice(tips)

def anonymize_ip(ip_address):
    """Basic IP anonymization for privacy"""
    if ip_address and ip_address.count('.') == 3:
        return '.'.join(ip_address.split('.')[:-1]) + '.xxx'
    return ip_address

def get_threat_status(request):
    """Analyze request headers for risk factors"""
    return {
        "malicious_ads": 0,
        "risk_score": calculate_risk_score(request),
        "protection_active": True
    }

def calculate_risk_score(request):
    """Calculate risk based on security headers"""
    score = 0
    if not request.headers.get('DNT'):  # No Do Not Track header
        score += 30
    if 'Chrome' not in request.headers.get('User-Agent', ''):  # Less secure browsers
        score += 20
    return min(score, 100)

def check_achievements(user, completed_tutorials, streak):
    """Check and award achievements based on user progress"""
    new_badges = []
    
    # Tutorial completion badges
    if completed_tutorials >= 5 and not user.add_badge("Quick Learner"):
        new_badges.append("Quick Learner")
    if completed_tutorials >= 10 and not user.add_badge("Cyber Guardian"):
        new_badges.append("Cyber Guardian")
    
    # Streak badges
    if streak >= 7 and not user.add_badge("Weekly Warrior"):
        new_badges.append("Weekly Warrior")
    if streak >= 30 and not user.add_badge("Monthly Master"):
        new_badges.append("Monthly Master")
    
    return new_badges

# ======== ROUTES ========
@app.route('/log_ad_click', methods=['POST'])
@csrf.exempt
def log_ad_click():
    """Logs ad click attempts for analytics"""
    try:
        data = request.get_json()
        if current_user.is_authenticated:
            user_id = current_user.id
        else:
            user_id = None
            
        new_detection = Detection(
            user_id=user_id,
            referrer=data.get('url'),
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(new_detection)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Ad click logged",
            "logged_at": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        app.logger.error(f"Failed to log ad click: {str(e)}")
        return jsonify({"status": "error"}), 500

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/', endpoint='index')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  

    security_context = {
        'last_scan': datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M %Z"),
        'user_ip': anonymize_ip(request.remote_addr),
        'threat_status': get_threat_status(request),
        'security_tip': get_random_security_tip(),
        'ad_protection_enabled': True,
        'known_ad_networks': [
            'doubleclick.net',
            'googlesyndication.com',
            'adservice.google',
            'adsrvr.org',
            'adnxs.com'
        ]
    }
    
    response = make_response(render_template('welcome.html', **security_context))
    response.headers.update({
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'X-Content-Type-Options': 'nosniff'
    })

    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    errors = {}

    if request.method == 'POST':
        try:
            # Validate CSRF token
            csrf_token = request.form.get('csrf_token')
            if csrf_token:
                validate_csrf(csrf_token)

            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            if not username:
                errors['username'] = 'Username is required'
            if not password:
                errors['password'] = 'Password is required'

            if not errors:
                user = User.query.filter_by(username=username).first()
                if user and user.check_password(password):
                    login_user(user)

                    # Update streak using timezone-aware UTC
                    now_utc = datetime.now(timezone.utc)
                    if user.last_activity and (now_utc.date() - user.last_activity.date()).days == 1:
                        user.streak += 1
                    elif (now_utc.date() - user.last_activity.date()).days > 1:
                        user.streak = 1

                    user.last_activity = now_utc
                    db.session.commit()

                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('dashboard'))
                else:
                    errors['auth'] = 'Invalid username or password'

        except ValidationError:
            errors['csrf'] = 'Session expired. Please refresh and try again.'
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}", exc_info=True)
            errors['auth'] = 'An unexpected error occurred. Please try again.'

    return render_template('login.html', errors=errors)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    errors = {}

    if request.method == 'POST':
        try:
            # Validate CSRF token
            csrf_token = request.form.get('csrf_token')
            if csrf_token:
                validate_csrf(csrf_token)

            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            # Validate username
            if not username:
                errors['username'] = 'Username is required'
            elif len(username) < 4:
                errors['username'] = 'Username must be at least 4 characters'
            elif not re.match(r'^\w+$', username):
                errors['username'] = 'Username can only contain letters, numbers and underscores'

            # Validate email
            if not email:
                errors['email'] = 'Email is required'
            elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                errors['email'] = 'Invalid email format'

            # Validate password
            if not password:
                errors['password'] = 'Password is required'
            elif len(password) < 8:
                errors['password'] = 'Password must be at least 8 characters'
            elif password != confirm_password:
                errors['confirm_password'] = 'Passwords do not match'

            # Check if user already exists
            if not errors:
                existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
                if existing_user:
                    if existing_user.username == username:
                        errors['username'] = 'Username already taken'
                    if existing_user.email == email:
                        errors['email'] = 'Email already registered'

            # Register new user
            if not errors:
                new_user = User(username=username, email=email)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.flush()  # Get new_user.id immediately

                # Initialize progress tracking
                for resource_name in SAFETY_RESOURCES:
                    progress = UserProgress(
                        user_id=new_user.id,
                        concept=resource_name,
                        mastery=0.0,
                        next_review=datetime.now(timezone.utc)
                    )
                    db.session.add(progress)

                db.session.commit()

                # Auto-login the user
                login_user(new_user)
                flash('Welcome aboard! Your account was created successfully.', 'success')

                # Redirect straight to dashboard
                return redirect(url_for('dashboard'))

        except ValidationError:
            errors['csrf'] = 'Session expired. Please refresh and try again.'
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}", exc_info=True)
            errors['auth'] = 'An unexpected error occurred. Please try again.'

    return render_template('register.html', errors=errors)

@app.route('/dashboard')
@login_required
def dashboard():
    """Enhanced dashboard route with comprehensive user progress tracking"""
    READING_SUMMARY = {
        1: "Introduction to cybersecurity fundamentals and core concepts",
        2: "Understanding phishing attacks and how to spot them",
        3: "Password security best practices and password managers",
        4: "Secure browsing techniques and HTTPS verification",
        5: "Email security essentials including attachment safety",
        6: "Social engineering awareness and prevention",
        7: "Mobile device security for smartphones and tablets",
        8: "Secure file handling and encryption methods",
        9: "Network security basics including firewalls and VPNs",
        10: "Advanced threat protection against malware"
    }

    try:
        # Ensure all datetime operations use timezone-aware objects
        now_utc = datetime.now(timezone.utc)
        
        # Create tutorials list
        tutorials = []
        for i in range(1, 11):
            tutorials.append({
                'id': i,
                'title': TUTORIALS[i]['title'],
                'url': TUTORIALS[i]['url']
            })

        # Build progress dictionary from passed results
        passed_results = QuizResult.query.filter_by(
            user_id=current_user.id,
            passed=True
        ).with_entities(QuizResult.tutorial_num).all()

        passed_tutorials = {result.tutorial_num for result in passed_results}
        progress = {i: i in passed_tutorials for i in range(1, 11)}

        # Completion percentage
        completed = sum(progress.values())
        total_tutorials = len(tutorials)
        percentage = (completed / total_tutorials) * 100 if total_tutorials > 0 else 0

        # Safety mastery score
        safety_mastery = db.session.query(
            db.func.coalesce(db.func.avg(UserProgress.mastery), 0.0)
        ).filter_by(user_id=current_user.id).scalar() or 0.0
        safety_mastery *= 100

        # Badge handling
        badges = []
        if current_user.badges:
            try:
                badges = json.loads(current_user.badges)
                if not isinstance(badges, list):
                    badges = []
            except (json.JSONDecodeError, TypeError):
                badges = []

        # Streak management
        streak = current_user.streak or 0

        # Check for new achievement badges
        try:
            new_badges = check_achievements(current_user, completed, streak)
            if new_badges:
                badges.extend(new_badges)
                current_user.badges = json.dumps(badges)
                db.session.commit()
                for badge in new_badges:
                    flash(f"🎉 Earned new badge: {badge}", "success")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error awarding badges: {str(e)}")

        # Final render
        return render_template('dashboard.html',
                           progress=progress,
                           percentage=round(percentage, 1),
                           tutorials=tutorials,
                           safety_mastery=round(safety_mastery, 1),
                           streak=streak,
                           badges=badges,
                           READING_SUMMARY=READING_SUMMARY)

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error in dashboard: {str(e)}")
        flash("A database error occurred. Please try again.", "danger")
        return redirect(url_for('index'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error in dashboard: {str(e)}", exc_info=True)
        flash("An unexpected error occurred. Our team has been notified.", "danger")
        return redirect(url_for('index'))
    
@app.route('/settings')
@login_required
def settings():
    return render_template("settings.html")

@app.route('/resources')
@login_required
def resources():
    """Display security resources organized by category"""
    try:
        # Organize resources by category
        categorized_resources = defaultdict(list)
        for name, data in SAFETY_RESOURCES.items():
            categorized_resources[data['category']].append({
                'name': name,
                'url': data['url'],
                'key_points': data['key_points']
            })

        return render_template('resources.html', 
                            resources=categorized_resources,
                            categories=sorted(categorized_resources.keys()))
    
    except Exception as e:
        app.logger.error(f"Error loading resources: {str(e)}", exc_info=True)
        flash("Failed to load resources. Please try again.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/tutorial/<int:tutorial_num>')
@login_required
def tutorial_view(tutorial_num):
    if tutorial_num > 10 or tutorial_num < 1:
        flash('Invalid tutorial number', 'danger')
        return redirect(url_for('dashboard'))

    if tutorial_num > 1:
        prev_completed = QuizResult.query.filter_by(
            user_id=current_user.id,
            tutorial_num=tutorial_num-1,
            passed=True
        ).first()
        if not prev_completed:
            flash('Complete earlier tutorials first.', 'warning')
            return redirect(url_for('dashboard'))

    tutorial = TUTORIALS.get(tutorial_num, {})

    return render_template('tutorial.html',
                        tutorial_num=tutorial_num,
                        tutorial=tutorial,
                        reading_text=READING_SUMMARY.get(tutorial_num, ""),
                        reading_url=tutorial.get("url", ""))

@app.route('/quiz')
@login_required
def quiz():
    try:
        tutorial_num = int(request.args.get('tutorial_num', 1))
        if not (1 <= tutorial_num <= 10):
            flash('Please select a valid tutorial (1-10)', 'warning')
            return redirect(url_for('dashboard'))

        if tutorial_num > 1:
            prev_completed = QuizResult.query.filter_by(
                user_id=current_user.id,
                tutorial_num=tutorial_num - 1,
                passed=True
            ).first()
            if not prev_completed:
                flash(f'Please complete tutorial {tutorial_num - 1} first', 'warning')
                return redirect(url_for('dashboard'))

        # Get questions for the quiz
        questions = quiz_engine.get_questions(tutorial_num, 5)  # Reduced to 5 for testing
        if not questions:
            flash('No questions available for this tutorial', 'warning')
            return redirect(url_for('dashboard'))

        return render_template('quiz_start.html',
                            tutorial_num=tutorial_num,
                            questions=questions,
                            tutorial_title=TUTORIALS[tutorial_num]["title"])

    except ValueError:
        flash('Invalid tutorial selection', 'danger')
        return redirect(url_for('dashboard'))
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error in quiz route: {str(e)}", exc_info=True)
        flash('A database error occurred', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    try:
        tutorial_num = int(request.form.get('tutorial_num'))
        questions_data = json.loads(request.form.get('questions', '[]'))
        
        # Calculate score
        correct = 0
        answer_details = []
        
        for i, question_data in enumerate(questions_data):
            user_answer = request.form.get(f'question_{i}')
            is_correct = user_answer == question_data['answer']
            
            if is_correct:
                correct += 1
                
            answer_details.append({
                'question': question_data['question'],
                'user_answer': user_answer,
                'correct_answer': question_data['answer'],
                'is_correct': is_correct,
                'explanation': question_data.get('explanation', {}).get('text', 'No explanation available')
            })
        
        score = correct / len(questions_data)
        passed = score >= 0.8  # 80% passing threshold

        # Save quiz result
        result = QuizResult(
            user_id=current_user.id,
            tutorial_num=tutorial_num,
            score=score,
            passed=passed,
            timestamp=datetime.now(timezone.utc),
            answer_details=json.dumps(answer_details)
        )
        db.session.add(result)
        
        # Update user progress and streak
        current_user.last_activity = datetime.now(timezone.utc)
        db.session.commit()
        
        # Show results
        return render_template('quiz_results.html',
                            tutorial_num=tutorial_num,
                            score=f"{score*100:.1f}%",
                            passed=passed,
                            correct=correct,
                            total=len(questions_data),
                            answer_details=answer_details,
                            tutorial_title=TUTORIALS[tutorial_num]["title"])
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting quiz: {str(e)}", exc_info=True)
        flash('An error occurred while processing your quiz results', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))

    # Calculate all metrics
    metrics = {
        'user_count': db.session.query(User).count(),
        'total_quizzes': db.session.query(QuizResult).count(),
        'passed_quizzes': db.session.query(QuizResult).filter_by(passed=True).count(),
        'avg_score': db.session.query(db.func.avg(QuizResult.score)).scalar() or 0,
        'active_users': db.session.query(User).filter(
            User.last_activity >= datetime.now(timezone.utc) - timedelta(days=30)
        ).count()
    }

    # Tutorial completion stats
    completions = {
        i: db.session.query(QuizResult.user_id)
          .filter_by(tutorial_num=i, passed=True)
          .distinct()
          .count()
        for i in range(1, 11)
    }

    return render_template('analytics.html',
                         metrics=metrics,
                         completions=completions)

@app.route('/api/report_click', methods=['POST'])
@csrf.exempt
@login_required
def report_click():
    data = request.get_json()
    tutorial_num = data.get('tutorial_num')
    app.logger.info(f"User {current_user.id} clicked on tutorial {tutorial_num}")
    return jsonify({"status": "success"})

@app.route('/quiz_review/<int:result_id>')
@login_required
def quiz_review(result_id):
    """Allow users to review past quiz attempts"""
    result = QuizResult.query.filter_by(
        id=result_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        answer_details = json.loads(result.answer_details) if result.answer_details else []
        review_data = {
            'tutorial_num': result.tutorial_num,
            'score': f"{result.score * 100:.1f}%",
            'passed': result.passed,
            'results': answer_details,
            'tutorial_title': TUTORIALS[result.tutorial_num]["title"],
            'resources': TUTORIALS[result.tutorial_num].get("resources", [])
        }
        return render_template('quiz_review.html', **review_data)
    except Exception as e:
        app.logger.error(f"Error loading quiz review: {str(e)}")
        flash('Could not load quiz review', 'danger')
        return redirect(url_for('dashboard'))
    
@app.template_filter('time_ago')
def time_ago_filter(dt):
    if not dt:
        return "Never"
    
    # Ensure now is timezone-aware UTC
    now = datetime.now(timezone.utc)
    
    # If dt is naive, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} year(s) ago"
    if diff.days > 30:
        return f"{diff.days // 30} month(s) ago"
    if diff.days > 0:
        return f"{diff.days} day(s) ago"
    if diff.seconds > 3600:
        return f"{diff.seconds // 3600} hour(s) ago"
    if diff.seconds > 60:
        return f"{diff.seconds // 60} minute(s) ago"
    return "Just now"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/toggle-dark-mode', methods=['POST'])
@login_required
def toggle_dark_mode():
    current = session.get('dark_mode', False)
    session['dark_mode'] = not current
    return jsonify({'dark_mode': session['dark_mode']})

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    if isinstance(e, HTTPException):
        return e
    return render_template("error.html", 
                         error=str(e), 
                         now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")), 500 

@app.route("/diagnostics")
@login_required
def diagnostics():
    return jsonify({
        "users": [{ "id": u.id, "username": u.username, "badges": u.badges } for u in User.query.all()],
        "detections": [{ "id": d.id, "referrer": d.referrer } for d in Detection.query.all()],
        "results": [{ "id": r.id, "score": r.score } for r in QuizResult.query.all()]
    })

def initialize_database():
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            app.logger.info('Database tables created successfully')

            # Create admin user if none exists
            if not User.query.filter_by(is_admin=True).first():
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    is_admin=True,
                    badges=json.dumps(['admin']),
                    last_activity=datetime.now(timezone.utc)
                )
                admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'admin123'))
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info('Initial admin user created')

            # Create tutorial entries if they don't exist
            if not Tutorial.query.first():
                for i, tutorial_data in TUTORIALS.items():
                    tutorial = Tutorial(
                        id=i,
                        title=tutorial_data['title'],
                        url=tutorial_data['url'],
                        resources=json.dumps(tutorial_data.get('resources', []))
                    )
                    db.session.add(tutorial)
                db.session.commit()
                app.logger.info('Tutorial entries created')

        except Exception as e:
            app.logger.error(f"Database initialization failed: {str(e)}")
            raise

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('app.log', encoding='utf-8')
        ]
    )
    
    initialize_database()
    app.run(debug=True, host='0.0.0.0', port=8080)
# app/utils.py
import requests
import hashlib
from flask import current_app
from .config import Config

def is_disposable_email(email):
    """
    Check if email is from a disposable email provider
    Requires either:
    1. A local database of disposable domains, or
    2. An API service like MailboxValidator
    """
    domain = email.split('@')[-1].lower()
    
    # Simple check against common disposable domains
    disposable_domains = {
        'mailinator.com', 'tempmail.com', 'guerrillamail.com',
        '10minutemail.com', 'throwawaymail.com'
    }
    
    if domain in disposable_domains:
        return True
        
    # For production, consider using an API:
    # response = requests.get(
    #     f"https://api.mailboxvalidator.com/v1/validation/single",
    #     params={'email': email, 'key': Config.MAILBOXVALIDATOR_API_KEY}
    # )
    # return response.json().get('is_disposable', False)
    
    return False

def is_breached_password(password):
    """
    Check if password has been compromised using HaveIBeenPwned API
    """
    if current_app.testing:  # Skip during tests
        return False
        
    # Hash the password with SHA-1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={'User-Agent': 'YourAppName'},
            timeout=2
        )
        
        # Check if suffix exists in the response
        for line in response.text.splitlines():
            if line.split(':')[0] == suffix:
                return True
                
    except requests.RequestException:
        # If API fails, we'll allow the password (fail open)
        current_app.logger.error("Failed to check password breach")
        return False
        
    return False

def verify_recaptcha(request):
    """
    Verify Google reCAPTCHA response
    """
    if current_app.testing or not Config.RECAPTCHA_ENABLED:
        return True
        
    secret_key = Config.RECAPTCHA_SECRET_KEY
    response = request.form.get('g-recaptcha-response')
    
    if not response:
        return False
        
    try:
        result = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': secret_key,
                'response': response,
                'remoteip': request.remote_addr
            },
            timeout=5
        ).json()
        
        return result.get('success', False)
        
    except requests.RequestException:
        current_app.logger.error("reCAPTCHA verification failed")
        return False
# ClickAware Extension System - Complete Jupyter Notebook
# Comprehensive guide to the cybersecurity education platform

# Import required libraries
import sys
import subprocess
import os
from IPython.display import Markdown, display, HTML
import json
def display_section(title, content, level=2):
    """Helper function to display formatted sections"""
    display(Markdown(f"{'#' * level} {title}"))
    if isinstance(content, dict):
        for key, value in content.items():
            display(Markdown(f"**{key}:** {value}"))
    elif isinstance(content, list):
        for item in content:
            display(Markdown(f"- {item}"))
    else:
        display(Markdown(content))

def check_environment():
    """Check Python environment and dependencies"""
    display_section("🔍 Environment Check", "")
    
    python_version = sys.version_info
    display(Markdown(f"- **Python Version:** {sys.version.split()[0]}"))
    display(Markdown(f"- **Python 3.8+ Compatible:** {'✅' if python_version.major == 3 and python_version.minor >= 8 else '❌'}"))
    
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        display(Markdown("- **Virtual Environment:** ✅ Active"))
    else:
        display(Markdown("- **Virtual Environment:** ⚠️ Not detected (recommended)"))
    
    return python_version.major == 3 and python_version.minor >= 8

# System Overview
display_section("🚀 ClickAware Extension System", {
    "Description": "A comprehensive Flask-based cybersecurity education and ad-click protection platform",
    "Purpose": "Protect users from malicious ads while educating them about cybersecurity threats", 
    "Core Features": "Ad-click detection, interactive tutorials, security quizzes, progress tracking"
})

# Run environment check
environment_ok = check_environment()
# Installation Guide
display_section("📦 Installation Steps", "Follow these steps to set up the ClickAware system:")

installation_steps = {
    "1. Clone Repository": "`git clone <repository-url>`",
    "2. Navigate to Directory": "`cd clickaware-extension`", 
    "3. Create Virtual Environment": "`python -m venv .venv`",
    "4. Activate Environment": "`source .venv/bin/activate` (Linux/Mac)<br>`.venv\\Scripts\\activate` (Windows)",
    "5. Install Dependencies": "`pip install -r requirements.txt`",
    "6. Apply Flask-Admin Patch": "`python patch_flask_admin.py`"
}

for step, command in installation_steps.items():
    display(Markdown(f"**{step}:** {command}"))
    display_section("⚙️ Environment Configuration", "Create a `.env` file with the following settings:")

env_config = {
    "FLASK_ENV": "development",
    "FLASK_DEBUG": "true", 
    "SECRET_KEY": "your-secret-key-here (min 64 characters)",
    "DATABASE_URL": "sqlite:///click_aware.db",
    "SUPPORT_EMAIL": "support@yourdomain.com",
    "ADMIN_PASSWORD": "secure-admin-password",
    "FEATURE_2FA_ENABLED": "true",
    "FEATURE_API_ENABLED": "true"
}

display(Markdown("```env"))
for key, value in env_config.items():
    display(Markdown(f"{key}={value}"))
display(Markdown("```"))

display_section("🗄️ Database Initialization", "Start the system to initialize the database:")
display(Markdown("```bash\npython app.py\n```"))
display(Markdown("This automatically creates:"))
display(Markdown("- Database tables and schema"))
display(Markdown("- Initial admin user account")) 
display(Markdown("- Tutorial content and security resources"))
display(Markdown("- Ad-click detection logging system"))

import os
from app import app as application

# Ensure Flask runs in production mode
application.config['ENV'] = 'production'
application.config['DEBUG'] = False

# Load environment variables from .env if present
if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv('.env')

# Export the WSGI callable expected by servers
# No additional code needed; 'application' is the Flask app instance.

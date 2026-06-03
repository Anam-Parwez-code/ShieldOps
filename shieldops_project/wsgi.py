import os
import sys

from django.core.wsgi import get_wsgi_application

# Ensuring local project directory is mapped to the runtime path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'shieldops_project.settings')

application = get_wsgi_application()
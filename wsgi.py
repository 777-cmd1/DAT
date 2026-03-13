"""
WSGI entry point — resolves the app/ package vs app.py naming conflict.
Used by:
  - Flask CLI:   FLASK_APP=wsgi.py flask db migrate
  - Gunicorn:    gunicorn wsgi:app  (alternative to app:app)
"""
import importlib.util
import sys
import os

# Load app.py explicitly so it doesn't conflict with the app/ package
_spec = importlib.util.spec_from_file_location(
    '_dat_mailer_app',
    os.path.join(os.path.dirname(__file__), 'app.py'),
)
_module = importlib.util.module_from_spec(_spec)
sys.modules['_dat_mailer_app'] = _module
_spec.loader.exec_module(_module)

app = _module.app
db  = _module.db

# Single worker required: send progress, TTL cache and memory:// rate limits live in process memory.
# Keep in sync with railway.json startCommand. Scaling beyond 1 worker needs Redis-backed state first.
web: gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120

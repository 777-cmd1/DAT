"""
Run this script ONCE after deploying to Railway to create your admin account.
Usage: python create_admin.py
"""
import json, os, secrets, hashlib, getpass

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def main():
    email = input("Admin email: ").strip().lower()
    name = input("Your name: ").strip()
    password = getpass.getpass("Password (min 6 chars): ")
    if len(password) < 6:
        print("Password too short!"); return

    users = []
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f: users = json.load(f)

    if any(u['email'].lower() == email for u in users):
        print("User already exists!"); return

    from datetime import datetime
    users.append({
        'email': email, 'name': name,
        'password': hash_password(password),
        'invited_by': 'system',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
    })
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
    print(f"✓ Admin account created for {email}")
    print(f"✓ You can now log in at your Railway URL")

if __name__ == '__main__':
    main()

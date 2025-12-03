# modules/auth.py
import hashlib
import re
from database.models import User
from database.db_session import create_session

def hash_password(password):
    """Securely hashes password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email_format(email):
    """
    Validates email structure using Regex.
    Must contain: chars + @ + domain + . + extension (2+ chars)
    Example: user@domain.com
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(pattern, email):
        return True
    return False

def validate_password_strength(password):
    """
    Enforces strong password policy:
    - At least 8 characters
    - Contains letters and numbers
    """
    if len(password) < 8:
        return False, "Password too weak (Min 8 chars)."
    if not re.search(r"[a-zA-Z]", password):
        return False, "Password must contain letters."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain numbers."
    return True, "Valid"

def check_email_availability(email):
    """Checks if email is already taken without creating a user."""
    session = create_session()
    existing = session.query(User).filter(User.email == email).first()
    session.close()
    if existing:
        return False, "Email already registered."
    return True, "Available"

def create_user_final(email, password, org_name):
    """Finalizes user creation after OTP verification."""
    session = create_session()
    # Double check just in case
    if session.query(User).filter(User.email == email).first():
        session.close()
        return False, "Error: User already exists."

    new_user = User(
        email=email, 
        password_hash=hash_password(password), 
        org_name=org_name
    )
    session.add(new_user)
    session.commit()
    session.close()
    return True, "Registration Successful! Please Login."

def login_user(email, password):
    session = create_session()
    user = session.query(User).filter(User.email == email).first()
    session.close()

    if not user:
        return False, "User not found."
    
    if user.password_hash == hash_password(password):
        return True, "Login Successful"
    else:
        return False, "Invalid Password."
import streamlit as st
import hashlib
import secrets
import string
import re
from typing import Dict, List
import time
from datetime import datetime, timedelta

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 32
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION = 300
VERIFICATION_CODE_EXPIRY = 30

def generate_salt() -> str:
    return secrets.token_hex(16)

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, "Password must be at least 8 characters long"
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, "Password must be less than 32 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character"
    return True, ""

def validate_email(email: str) -> tuple[bool, str]:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Please enter a valid email address"
    
    # Check if email is already registered
    if 'users' in st.session_state:
        if any(user.get('email') == email for user in st.session_state.users):
            return False, "Email is already registered"
    
    return True, ""

def generate_verification_code() -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def store_verification_code(email: str, code: str) -> None:
    if 'email_verification' not in st.session_state:
        st.session_state.email_verification = {}
    
    expiry = datetime.now() + timedelta(minutes=VERIFICATION_CODE_EXPIRY)
    st.session_state.email_verification[email] = {
        'code': code,
        'expiry': expiry
    }

def verify_email_code(email: str, code: str) -> bool:
    if 'email_verification' not in st.session_state:
        return False
    
    verification = st.session_state.email_verification.get(email)
    if not verification:
        return False
    
    current_time = datetime.now()
    if current_time > verification['expiry']:
        return False
    
    return verification['code'] == code

def validate_username(username: str, users: List[Dict]) -> tuple[bool, str]:
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"

    from db import get_user
    if get_user(username):
        return False, "Username already exists"
    
    return True, ""

def signup_page(users: List[Dict]) -> None:
    st.title("HRMS Sign Up")
    if 'signup_attempts' not in st.session_state:
        st.session_state.signup_attempts = {}
    if 'signup_lockout' not in st.session_state:
        st.session_state.signup_lockout = {}
    
    with st.form("signup_form"):
        username = st.text_input("Username", key="signup_username").strip()
        password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm_password")
        role = st.selectbox(
            "Role",
            ["hr", "employee"],
            key="signup_role"
        )
        if password:
            is_valid, error_msg = validate_password(password)
            if is_valid:
                st.success("Password meets requirements")
            else:
                st.warning(error_msg)
        
        if st.form_submit_button("Sign Up"):
            if username in st.session_state.signup_lockout:
                lockout_time = st.session_state.signup_lockout[username]
                if datetime.now() < lockout_time:
                    remaining_time = (lockout_time - datetime.now()).seconds
                    st.error(f"Too many attempts. Please try again in {remaining_time} seconds.")
                    return
            validation_errors = []
            is_valid, error_msg = validate_username(username, users)
            if not is_valid:
                validation_errors.append(error_msg)
            if not password or not confirm_password:
                validation_errors.append("Please enter both password and confirmation")
            elif password != confirm_password:
                validation_errors.append("Passwords do not match")
            else:
                is_valid, error_msg = validate_password(password)
                if not is_valid:
                    validation_errors.append(error_msg)
            if validation_errors:
                for error in validation_errors:
                    st.error(error)
                return
            try:
                from db import create_user
                create_user(username, password, role)
                st.success("Account created successfully! Redirecting to login page...")
                st.session_state.show_login_tab = True
                st.session_state.new_user_username = username

                time.sleep(2)
                st.rerun()
                
            except Exception as e:
                st.error(f"Error creating account: {str(e)}")
                st.session_state.error_log = st.session_state.get('error_log', [])
                st.session_state.error_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'username': username
                })
import streamlit as st
import hashlib
from typing import Dict, List, Optional
from sign import signup_page, hash_password
import time
from datetime import datetime, timedelta
from db import get_user, verify_password


MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION = 300
SESSION_TIMEOUT = 1800

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": ["Employee Management", "Leave Management", "Attendance Tracking", "Asset Management", "Task Management", "AI Assistant"],
    "hr": ["Employee Management", "Leave Management", "Attendance Tracking", "Task Management", "AI Assistant"],
    "employee": ["Leave Management", "Attendance Tracking", "Task Management"]
}

def check_session_timeout() -> bool:
    if 'last_activity' not in st.session_state:
        return False
    
    last_activity = datetime.fromisoformat(st.session_state.last_activity)
    return (datetime.now() - last_activity).seconds > SESSION_TIMEOUT

def update_last_activity() -> None:
    st.session_state.last_activity = datetime.now().isoformat()

def login_page(users: List[Dict]) -> None:
    st.title("SELVAN PVT.LTD")
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    if 'login_lockout' not in st.session_state:
        st.session_state.login_lockout = {}
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now().isoformat()
    if check_session_timeout():
        st.warning("Your session has expired. Please log in again.")
        return
    if 'show_login_tab' not in st.session_state:
        st.session_state.show_login_tab = False
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username").strip()
            password = st.text_input("Password", type="password", key="login_password")
            remember_me = st.checkbox("Remember Me", key="remember_me")
            
            if st.form_submit_button("Login"):
                handle_login(username, password, users)
    
    with tab2:
        signup_page(users)

def handle_login(username: str, password: str, users: List[Dict]) -> None:
    if username in st.session_state.login_lockout:
        lockout_time = st.session_state.login_lockout[username]
        if datetime.now() < lockout_time:
            remaining_time = (lockout_time - datetime.now()).seconds
            st.error(f"Account locked. Please try again in {remaining_time} seconds.")
            return
    if not username or not password:
        st.error("Please enter both username and password")
        return
    user = get_user(username)
    
    if not user:
        st.error("Invalid username")
        return

    if username == "admin" and user.get("is_builtin", False):
        handle_admin_login(user, password)

    elif verify_password(user["password"], password, user["salt"]):
        handle_successful_login(user)
    else:
        handle_failed_login(username)

def handle_admin_login(user: Dict, password: str) -> None:

    if password == "Admin@123":
        complete_login(user)
    else:
        st.error("Invalid password for admin account")

def handle_successful_login(user: Dict) -> None:
    complete_login(user)

def handle_failed_login(username: str) -> None:

    st.session_state.login_attempts[username] = st.session_state.login_attempts.get(username, 0) + 1
    if st.session_state.login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
        st.session_state.login_lockout[username] = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
        st.error(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION} seconds.")
    else:
        st.error("Invalid password")

def complete_login(user: Dict) -> None:
    st.session_state.authenticated = True
    st.session_state.current_user = user
    st.session_state.last_activity = datetime.now().isoformat()
    if user["username"] in st.session_state.login_attempts:
        del st.session_state.login_attempts[user["username"]]
    user["last_login"] = datetime.now().isoformat()
    from db import update_user
    update_user(user["username"], {"last_login": user["last_login"]})
    
    st.success("Login successful!")
    st.rerun()

def logout() -> None:
    if st.session_state.get("authenticated"):
        # Log logout event
        st.session_state.logout_log = st.session_state.get('logout_log', [])
        st.session_state.logout_log.append({
            'timestamp': datetime.now().isoformat(),
            'username': st.session_state.current_user.get('username')
        })
    
    # Clear all session data
    for key in list(st.session_state.keys()):
        if key not in ['users', 'employees', 'leaves', 'attendance', 'assets']:
            del st.session_state[key]
    
    st.rerun()

def is_authenticated() -> bool:
    if not st.session_state.get("authenticated"):
        return False
    
    # Check session timeout
    if check_session_timeout():
        return False
    
    update_last_activity()
    return True

def get_current_user() -> Optional[Dict]:
    if not is_authenticated():
        return None
    return st.session_state.get("current_user")

def has_permission(module: str, employee_id: str = None) -> bool:
    current_user = get_current_user()
    if not current_user:
        return False
    
    # If checking specific employee permissions
    if employee_id:
        # Get the employee's role
        from db import get_employee
        employee = get_employee(employee_id)
        if not employee:
            return False
            
        # If the current user is the employee or is admin/hr, allow access
        if (current_user["username"] == employee.get("username") or 
            current_user["role"] in ["admin", "hr"]):
            return True
        return False
    
    # Regular role-based permission check
    role = current_user.get("role", "employee")
    return module in ROLE_PERMISSIONS.get(role, [])

def get_available_modules() -> List[str]:
    current_user = get_current_user()
    if not current_user:
        return []
    
    role = current_user.get("role", "employee")
    return ROLE_PERMISSIONS.get(role, [])
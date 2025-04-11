import streamlit as st
import pandas as pd
import google.generativeai as genai
from dotenv import load_dotenv
import os
from typing import List, Dict, Any, Optional
import json
import traceback
import hashlib
import logging
from login import login_page, logout, is_authenticated, get_current_user, has_permission, get_available_modules
from sign import generate_salt, hash_password
from task_management import task_management
from db import (
    get_all_employees, create_employee, get_employee, update_employee,
    create_task, get_task, update_task, get_user_tasks,
    create_leave, get_employee_leaves, update_leave,
    create_attendance, get_employee_attendance,
    create_asset, get_asset, update_asset, db, create_user, get_user
)
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configure Google AI
try:
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
except Exception as e:
    logger.error(f"Error configuring Google AI: {str(e)}")
    st.error(f"Error configuring Google AI: {str(e)}")

# Default users with secure passwords
DEFAULT_USERS: List[Dict[str, Any]] = [
    {
        "username": "admin",
        "password": hash_password("Admin@123", generate_salt()),  # Strong password
        "salt": generate_salt(),
        "role": "admin",
        "created_at": "2024-01-01T00:00:00",
        "last_login": None,
        "failed_attempts": 0,
        "is_builtin": True  # Mark as built-in admin
    }
]

# Initialize session state
def initialize_session_state():
    if 'employees' not in st.session_state:
        st.session_state.employees = []
    if 'leaves' not in st.session_state:
        st.session_state.leaves = []
    if 'attendance' not in st.session_state:
        st.session_state.attendance = []
    if 'assets' not in st.session_state:
        st.session_state.assets = []
    if 'users' not in st.session_state:
        st.session_state.users = DEFAULT_USERS
        
        # Ensure admin user exists in database
        from db import get_user, create_user
        admin_user = get_user("admin")
        if not admin_user:
            create_user("admin", "Admin@123", "admin")
            st.info("Created built-in admin account")
            
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None

try:
    initialize_session_state()
except Exception as e:
    st.error(f"Error initializing session state: {str(e)}")

def generate_llm_response(prompt: str) -> str:
    try:
        # Try with gemini-pro model first
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        try:
            # Fallback to text-bison model
            model = genai.GenerativeModel('text-bison')
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            # If both models fail, return a helpful error message
            error_msg = f"Error generating response: {str(e)}"
            logger.error(error_msg)
            return f"""I apologize, but I'm currently unable to generate a response using the AI model. 
This could be due to:
1. API configuration issues
2. Model availability
3. Network connectivity

Please try the following:
1. Check your API key configuration
2. Verify your internet connection
3. Try again later

If the issue persists, please contact your system administrator."""

def validate_employee_data(employee_data: Dict[str, Any]) -> Optional[str]:
    required_fields = ["employee_id", "name", "email", "department", "position", "username"]
    for field in required_fields:
        if not employee_data.get(field):
            return f"Please fill in the {field} field"
    
    if "@" not in employee_data["email"] or "." not in employee_data["email"]:
        return "Please enter a valid email address"
    
    if get_employee(employee_data["employee_id"]):
        return "Employee ID already exists"
    
    if get_user(employee_data["username"]):
        return "Username already exists"
    
    return None

def create_new_employee(employee_data: Dict[str, Any], current_user: Dict[str, Any]) -> bool:
    try:
        # Create user account
        create_user(employee_data["username"], employee_data["password"], employee_data["role"])
        
        # Add new employee
        new_employee = {
            "employee_id": employee_data["employee_id"],
            "name": employee_data["name"],
            "email": employee_data["email"],
            "phone": employee_data.get("phone", ""),
            "department": employee_data["department"],
            "position": employee_data["position"],
            "hire_date": employee_data.get("hire_date", datetime.now().isoformat()),
            "salary": employee_data.get("salary", 0),
            "username": employee_data["username"],
            "created_by": current_user["username"],
            "created_at": datetime.now().isoformat()
        }
        
        create_employee(new_employee)
        return True
    except Exception as e:
        st.error(f"Error creating employee: {str(e)}")
        return False

def employee_management() -> None:
    st.title("Employee Management")
    
    current_user = get_current_user()
    if not current_user:
        st.error("Please log in to access employee management")
        return
    
    employees = get_all_employees()
    if not employees:
        st.warning("No employees found")
        return
    if current_user["role"] in ["admin", "hr"]:
        show_employee_management_form(current_user)

    st.subheader("Employee List")
    show_employee_list(employees, current_user)

def show_employee_management_form(current_user: Dict[str, Any]) -> None:
    with st.expander("Add New Employee"):
        with st.form("employee_form"):
            st.subheader("Add New Employee")
            employee_data = get_employee_form_data(current_user)
            
            if st.form_submit_button("Add Employee"):
                error = validate_employee_data(employee_data)
                if error:
                    st.error(error)
                    return
                
                if create_new_employee(employee_data, current_user):
                    st.success("Employee added successfully!")

def get_employee_form_data(current_user: Dict[str, Any]) -> Dict[str, Any]:
    employee_data = {
        "employee_id": st.text_input("Employee ID", key="employee_id"),
        "name": st.text_input("Name", key="employee_name"),
        "email": st.text_input("Email", key="employee_email"),
        "phone": st.text_input("Phone", key="employee_phone"),
        "department": st.selectbox(
            "Department",
            ["HR", "Finance", "IT", "Marketing", "Operations"],
            key="employee_department"
        ),
        "position": st.text_input("Position", key="employee_position"),
        "hire_date": st.date_input("Hire Date", key="employee_hire_date"),
        "salary": st.number_input("Salary", min_value=0, key="employee_salary"),
        "username": st.text_input("Username", key="employee_username"),
        "password": st.text_input("Password", type="password", key="employee_password"),
        "confirm_password": st.text_input("Confirm Password", type="password", key="employee_confirm_password")
    }
    
    if current_user["role"] == "admin":
        employee_data["role"] = st.selectbox(
            "Role",
            ["hr", "employee"],
            key="employee_role"
        )
    else:
        employee_data["role"] = "employee"
    
    return employee_data

def show_employee_list(employees: List[Dict[str, Any]], current_user: Dict[str, Any]) -> None:
    if current_user["role"] not in ["admin", "hr"]:
        emp = next((e for e in employees if e["username"] == current_user["username"]), None)
        if emp:
            employees = [emp]
        else:
            st.error("Employee record not found")
            return

    table_data = []
    for emp in employees:
        row = {
            "Employee ID": emp["employee_id"],
            "Name": emp["name"],
            "Department": emp["department"],
            "Position": emp["position"],
            "Email": emp["email"],
            "Phone": emp["phone"],
            "Hire Date": emp["hire_date"],
            "Salary": f"${emp['salary']:,}" if emp.get("salary") else "N/A",
        }
        table_data.append(row)

    if table_data:
        df = pd.DataFrame(table_data)

        df.set_index("Employee ID", inplace=True)

        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Actions": st.column_config.Column(
                    "Actions",
                    help="Click to edit employee details",
                    width="small"
                )
            }
        )

        for emp in employees:
            if st.button("Edit", key=f"edit_{emp['employee_id']}"):
                show_employee_details(emp, current_user)
    else:
        st.warning("No employees found")

def show_employee_details(emp: Dict[str, Any], current_user: Dict[str, Any]) -> None:
    st.write(f"**Department:** {emp['department']}")
    st.write(f"**Position:** {emp['position']}")
    st.write(f"**Email:** {emp['email']}")
    st.write(f"**Phone:** {emp['phone']}")
    st.write(f"**Hire Date:** {emp['hire_date']}")
    st.write(f"**Salary:** {emp['salary']}")
    st.write(f"**Username:** {emp['username']}")

    with st.form(f"edit_form_{emp['employee_id']}"):
        st.subheader("Edit Employee Details")
        update_data = get_employee_update_data(emp, current_user)
        
        if st.form_submit_button("Update Employee"):
            try:
                update_employee(emp["employee_id"], update_data)
                st.success("Employee details updated successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error updating employee: {str(e)}")

def get_employee_update_data(emp: Dict[str, Any], current_user: Dict[str, Any]) -> Dict[str, Any]:
    update_data = {
        "name": st.text_input("Name", value=emp["name"], key=f"edit_name_{emp['employee_id']}"),
        "email": st.text_input("Email", value=emp["email"], key=f"edit_email_{emp['employee_id']}"),
        "phone": st.text_input("Phone", value=emp["phone"], key=f"edit_phone_{emp['employee_id']}")
    }
    
    if current_user["role"] in ["admin", "hr"]:
        update_data.update({
            "department": st.selectbox(
                "Department",
                ["HR", "Finance", "IT", "Marketing", "Operations"],
                index=["HR", "Finance", "IT", "Marketing", "Operations"].index(emp["department"]),
                key=f"edit_dept_{emp['employee_id']}"
            ),
            "position": st.text_input("Position", value=emp["position"], key=f"edit_position_{emp['employee_id']}"),
            "salary": st.number_input("Salary", value=emp["salary"], min_value=0, key=f"edit_salary_{emp['employee_id']}")
        })
    else:
        update_data.update({
            "department": emp["department"],
            "position": emp["position"],
            "salary": emp["salary"]
        })
    
    return update_data

def leave_management():
    try:
        st.header("Leave Management")
        current_user = get_current_user()
        if not current_user:
            st.error("Please log in to access leave management")
            return
        
        employees = get_all_employees()
        if not employees:
            st.warning("Please add employees first before managing leaves")
            return
        with st.expander("Request Leave"):
            with st.form("leave_form"):
                if current_user["role"] in ["admin", "hr"]:
                    employee_options = [
                        f"{emp['employee_id']} - {emp['name']}" 
                        for emp in employees
                    ]
                    employee_id = st.selectbox(
                        "Employee",
                        employee_options,
                        key="leave_emp_select"
                    )
                else:
                    emp = next((e for e in employees if e["username"] == current_user["username"]), None)
                    if emp:
                        employee_id = f"{emp['employee_id']} - {emp['name']}"
                        st.write(f"Employee: {emp['name']}")
                    else:
                        st.error("Employee record not found")
                        return
                
                start_date = st.date_input("Start Date", key="leave_start_date")
                end_date = st.date_input("End Date", key="leave_end_date")
                leave_type = st.selectbox(
                    "Leave Type",
                    ["Annual", "Sick", "Personal", "Other"],
                    key="leave_type"
                )
                reason = st.text_area("Reason", key="leave_reason")
                
                if st.form_submit_button("Submit Leave Request"):
                    if not all([employee_id, start_date, end_date, leave_type, reason]):
                        st.error("Please fill in all required fields")
                        return
                    
                    if end_date < start_date:
                        st.error("End date cannot be before start date")
                        return
                    
                    try:
                        emp_id, emp_name = employee_id.split(" - ")
                        
                        new_leave = {
                            "leave_id": len(get_employee_leaves(emp_id)) + 1,
                            "employee_id": emp_id,
                            "employee_name": emp_name,
                            "start_date": str(start_date),
                            "end_date": str(end_date),
                            "type": leave_type,
                            "reason": reason,
                            "status": "Pending",
                            "created_at": datetime.now().isoformat()
                        }
                        create_leave(new_leave)
                        st.success("Leave request submitted successfully!")
                    except Exception as e:
                        st.error(f"Error creating leave request: {str(e)}")

        if current_user["role"] in ["admin", "hr"]:
            leaves = []
            for emp in employees:
                leaves.extend(get_employee_leaves(emp["employee_id"]))
        else:
            emp = next((e for e in employees if e["username"] == current_user["username"]), None)
            if emp:
                leaves = get_employee_leaves(emp["employee_id"])
            else:
                leaves = []
        
        if leaves:
            st.subheader("Leave Requests")
            for leave in leaves:
                try:
                    if leave['status'] == 'Pending':
                        col1, col2, col3 = st.columns([2, 1, 1])
                        with col1:
                            st.write(f"Employee: {leave.get('employee_name', 'Unknown')}")
                            st.write(f"Type: {leave.get('type', 'Unknown')}")
                            st.write(f"Period: {leave.get('start_date', 'Unknown')} to {leave.get('end_date', 'Unknown')}")
                            st.write(f"Reason: {leave.get('reason', 'No reason provided')}")
                        with col2:
                            if current_user["role"] in ["admin", "hr"]:
                                if st.button("Approve", key=f"approve_{leave['leave_id']}"):
                                    update_leave(leave["leave_id"], {"status": "Approved"})
                                    st.success("Leave request approved!")
                                    st.rerun()
                        with col3:
                            if current_user["role"] in ["admin", "hr"]:
                                if st.button("Reject", key=f"reject_{leave['leave_id']}"):
                                    update_leave(leave["leave_id"], {"status": "Rejected"})
                                    st.error("Leave request rejected!")
                                    st.rerun()
                        st.divider()
                except Exception as e:
                    st.error(f"Error displaying leave request: {str(e)}")
        else:
            st.info("No leave requests found.")
    except Exception as e:
        st.error(f"An error occurred in leave management: {str(e)}")
        st.error(traceback.format_exc())

def attendance_tracking():
    try:
        st.header("Attendance Tracking")
        
        employees = get_all_employees()
        if not employees:
            st.warning("Please add employees first before tracking attendance")
            return

        with st.expander("Mark Attendance"):
            with st.form("attendance_form"):
                employee_options = [
                    f"{emp['employee_id']} - {emp['name']}" 
                    for emp in employees
                ]
                
                employee_id = st.selectbox(
                    "Employee",
                    employee_options,
                    key="attendance_emp_select"
                )
                date = st.date_input("Date", key="attendance_date")
                status = st.selectbox(
                    "Status",
                    ["Present", "Absent", "Late", "Half Day"],
                    key="attendance_status"
                )
                notes = st.text_area("Notes", key="attendance_notes")
                
                if st.form_submit_button("Submit Attendance"):
                    if not all([employee_id, date, status]):
                        st.error("Please fill in all required fields")
                        return
                    
                    try:
                        emp_id, emp_name = employee_id.split(" - ")
                        
                        new_attendance = {
                            "attendance_id": len(get_employee_attendance(emp_id)) + 1,
                            "employee_id": emp_id,
                            "employee_name": emp_name,
                            "date": str(date),
                            "status": status,
                            "notes": notes
                        }
                        create_attendance(new_attendance)
                        st.success("Attendance recorded successfully!")
                    except Exception as e:
                        st.error(f"Error recording attendance: {str(e)}")
        attendance_records = []
        for emp in employees:
            attendance_records.extend(get_employee_attendance(emp["employee_id"]))
        
        if attendance_records:
            st.subheader("Attendance Records")

            col1, col2 = st.columns(2)
            with col1:
                search_term = st.text_input("Search by Employee ID or Name")
            with col2:
                filter_status = st.selectbox(
                    "Filter by Status",
                    ["All"] + list(set(att["status"] for att in attendance_records)),
                    key="attendance_filter"
                )
            filtered_attendance = attendance_records
            if search_term:
                filtered_attendance = [
                    att for att in filtered_attendance
                    if (search_term.lower() in att["employee_id"].lower() or
                        search_term.lower() in att["employee_name"].lower())
                ]
            if filter_status != "All":
                filtered_attendance = [
                    att for att in filtered_attendance
                    if att["status"] == filter_status
                ]
            
            if filtered_attendance:
                try:
                    df = pd.DataFrame(filtered_attendance)
                    columns = ["attendance_id", "employee_id", "employee_name", "date", "status", "notes"]
                    df = df[columns]
                    st.dataframe(df)
                except Exception as e:
                    st.error(f"Error displaying attendance records: {str(e)}")
            else:
                st.info("No attendance records found matching the search criteria.")
    except Exception as e:
        st.error(f"An error occurred in attendance tracking: {str(e)}")
        st.error(traceback.format_exc())

def asset_management():
    st.header("Asset Management")
    with st.expander("Add New Asset"):
        with st.form("asset_form"):
            name = st.text_input("Asset Name")
            asset_type = st.text_input("Asset Type")
            serial_number = st.text_input("Serial Number")
            assigned_to = st.selectbox(
                "Assigned To",
                ["Not Assigned"] + [f"{emp['employee_id']} - {emp['name']}" 
                                  for emp in get_all_employees()]
            )
            
            if st.form_submit_button("Add Asset"):
                all_assets = list(db.assets.find())
                next_id = max([asset.get('asset_id', 0) for asset in all_assets], default=0) + 1
                
                new_asset = {
                    "asset_id": next_id,
                    "name": name,
                    "type": asset_type,
                    "serial_number": serial_number,
                    "assigned_to": assigned_to if assigned_to != "Not Assigned" else None
                }
                create_asset(new_asset)
                st.success("Asset added successfully!")

    all_assets = list(db.assets.find())
    if all_assets:
        st.subheader("Asset List")
        df = pd.DataFrame(all_assets)
        st.dataframe(df)

def ai_assistant():
    st.header("AI Assistant")
    
    user_input = st.text_area("Ask a question about HR management:")
    if st.button("Get AI Response"):
        if user_input:
            try:
                # Get current statistics
                total_employees = len(get_all_employees())
                total_leaves = len(list(db.leaves.find()))
                total_assets = len(list(db.assets.find()))
                total_tasks = len(list(db.tasks.find()))
                
                prompt = f"""
                You are an HR management assistant. Please provide helpful and professional advice on the following question:
                {user_input}
                
                Consider the following context:
                - We have {total_employees} employees
                - We have {total_leaves} leave requests
                - We have {total_assets} assets
                - We have {total_tasks} tasks
                
                Please provide a detailed and helpful response.
                """
                
                response = generate_llm_response(prompt)
                st.write("AI Response:")
                st.write(response)
            except Exception as e:
                st.error(f"Error generating response: {str(e)}")
        else:
            st.warning("Please enter a question first.")

def signup_page():
    st.title("HRMS Sign Up")
    
    with st.form("signup_form"):
        username = st.text_input("Username", key="signup_username")
        password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm_password")
        role = st.selectbox(
            "Role",
            ["hr", "employee"],
            key="signup_role"
        )
        
        if st.form_submit_button("Sign Up"):
            # Validation
            if not all([username, password, confirm_password]):
                st.error("Please fill in all fields")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
                return
            
            if len(password) < 8:
                st.error("Password must be at least 8 characters long")
                return
            
            # Check if username already exists
            if any(user["username"] == username for user in st.session_state.users):
                st.error("Username already exists")
                return
            
            # Add new user
            try:
                new_user = {
                    "username": username,
                    "password": hash_password(password, st.session_state.users[0]['salt']),
                    "role": role
                }
                st.session_state.users.append(new_user)
                st.success("Account created successfully! Please login.")
                st.rerun()
            except Exception as e:
                st.error(f"Error creating account: {str(e)}")

def main() -> None:
    st.set_page_config(
        page_title="SELVAN PVT.LTD",
        page_icon="👥",
        layout="wide"
    )

    if not is_authenticated():
        login_page(DEFAULT_USERS)
        return

    # Main application layout
    st.title("Human Resource Management System")
    
    # Add user info and logout button in sidebar
    st.sidebar.title("SELVAN PVT.LTD")
    current_user = get_current_user()
    if current_user:
        st.sidebar.write(f"Logged in as: {current_user['username']}")
        st.sidebar.write(f"Role: {current_user['role'].upper()}")
    if st.sidebar.button("Logout"):
        logout()
    
    # Get available modules based on user role
    available_modules = get_available_modules()
    
    # Sidebar navigation with role-based access
    page = st.sidebar.radio(
        "Select Module",
        available_modules
    )
    
    # Check permission before rendering module
    if not has_permission(page):
        st.error("You don't have permission to access this module.")
        return
    
    # Route to appropriate module
    module_routes = {
        "Employee Management": employee_management,
        "Leave Management": leave_management,
        "Attendance Tracking": attendance_tracking,
        "Asset Management": asset_management,
        "Task Management": task_management,
        "AI Assistant": ai_assistant
    }
    
    if page in module_routes:
        module_routes[page]()
    else:
        st.error("Invalid module selected")

if __name__ == "__main__":
    main() 
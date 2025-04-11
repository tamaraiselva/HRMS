from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import hashlib
import binascii
from typing import Dict, List, Any, Optional, Tuple
import streamlit as st
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

try:
    client = MongoClient(os.getenv("MONGODB_URI"))
    db = client[os.getenv("HRMS")]
    logger.info("Successfully connected to MongoDB")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    st.error("Failed to connect to database. Please check your connection settings.")
    raise

users_collection = db["users"]
employees_collection = db["employees"]
tasks_collection = db["tasks"]
leaves_collection = db["leaves"]
attendance_collection = db["attendance"]
assets_collection = db["assets"]

def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    if salt is None:
        salt = binascii.hexlify(os.urandom(32)).decode()
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return binascii.hexlify(key).decode(), salt

def verify_password(stored_password: str, provided_password: str, salt: str) -> bool:
    hashed_password, _ = hash_password(provided_password, salt)
    return hashed_password == stored_password

def handle_database_error(operation: str, error: Exception) -> bool:
    error_msg = f"Error in {operation}: {str(error)}"
    logger.error(error_msg)
    st.error(error_msg)
    return False

def get_user(username: str) -> Optional[Dict[str, Any]]:
    return users_collection.find_one({"username": username})

def create_user(username: str, password: str, role: str) -> bool:
    try:
        hashed_password, salt = hash_password(password)
        user = {
            "username": username,
            "password": hashed_password,
            "salt": salt,
            "role": role,
            "created_at": datetime.now(),
            "last_login": None,
            "failed_attempts": 0
        }
        users_collection.insert_one(user)
        logger.info(f"Successfully created user: {username}")
        return True
    except Exception as e:
        return handle_database_error("create_user", e)

def update_user(username: str, update_data: Dict[str, Any]) -> bool:
    try:
        result = users_collection.update_one(
            {"username": username},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            logger.info(f"Successfully updated user: {username}")
            return True
        else:
            logger.warning(f"No changes made to user: {username}")
            return False
    except Exception as e:
        return handle_database_error("update_user", e)

def get_employee(employee_id: str) -> Optional[Dict[str, Any]]:
    return employees_collection.find_one({"employee_id": employee_id})

def create_employee(employee_data: Dict[str, Any]) -> bool:
    try:
        employees_collection.insert_one(employee_data)
        logger.info(f"Successfully created employee: {employee_data.get('employee_id')}")
        return True
    except Exception as e:
        return handle_database_error("create_employee", e)

def update_employee(employee_id: str, update_data: Dict[str, Any]) -> bool:
    try:
        result = employees_collection.update_one(
            {"employee_id": employee_id},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            logger.info(f"Successfully updated employee: {employee_id}")
            return True
        else:
            logger.warning(f"No changes made to employee: {employee_id}")
            return False
    except Exception as e:
        return handle_database_error("update_employee", e)

def get_all_employees() -> List[Dict[str, Any]]:
    return list(employees_collection.find())

def create_task(task_data: Dict[str, Any]) -> bool:
    try:
        tasks_collection.insert_one(task_data)
        logger.info(f"Successfully created task: {task_data.get('task_id')}")
        return True
    except Exception as e:
        return handle_database_error("create_task", e)

def get_task(task_id: int) -> Optional[Dict[str, Any]]:
    return tasks_collection.find_one({"task_id": task_id})

def update_task(task_id: int, update_data: Dict[str, Any]) -> bool:
    try:
        result = tasks_collection.update_one(
            {"task_id": task_id},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            logger.info(f"Successfully updated task: {task_id}")
            return True
        else:
            logger.warning(f"No changes made to task: {task_id}")
            return False
    except Exception as e:
        return handle_database_error("update_task", e)

def get_user_tasks(username: str) -> List[Dict[str, Any]]:
    return list(tasks_collection.find({"assignee": username}))

def create_leave(leave_data: Dict[str, Any]) -> bool:
    try:
        leaves_collection.insert_one(leave_data)
        logger.info(f"Successfully created leave request: {leave_data.get('leave_id')}")
        return True
    except Exception as e:
        return handle_database_error("create_leave", e)

def get_employee_leaves(employee_id: str) -> List[Dict[str, Any]]:
    return list(leaves_collection.find({"employee_id": employee_id}))

def update_leave(leave_id: int, update_data: Dict[str, Any]) -> bool:
    try:
        result = leaves_collection.update_one(
            {"leave_id": leave_id},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            logger.info(f"Successfully updated leave request: {leave_id}")
            return True
        else:
            logger.warning(f"No changes made to leave request: {leave_id}")
            return False
    except Exception as e:
        return handle_database_error("update_leave", e)

def create_attendance(attendance_data: Dict[str, Any]) -> bool:
    try:
        attendance_collection.insert_one(attendance_data)
        logger.info(f"Successfully created attendance record: {attendance_data.get('attendance_id')}")
        return True
    except Exception as e:
        return handle_database_error("create_attendance", e)

def get_employee_attendance(employee_id: str) -> List[Dict[str, Any]]:
    return list(attendance_collection.find({"employee_id": employee_id}))

def create_asset(asset_data: Dict[str, Any]) -> bool:
    try:
        assets_collection.insert_one(asset_data)
        logger.info(f"Successfully created asset: {asset_data.get('asset_id')}")
        return True
    except Exception as e:
        return handle_database_error("create_asset", e)

def get_asset(asset_id: int) -> Optional[Dict[str, Any]]:
    return assets_collection.find_one({"asset_id": asset_id})

def update_asset(asset_id: int, update_data: Dict[str, Any]) -> bool:
    try:
        result = assets_collection.update_one(
            {"asset_id": asset_id},
            {"$set": update_data}
        )
        if result.modified_count > 0:
            logger.info(f"Successfully updated asset: {asset_id}")
            return True
        else:
            logger.warning(f"No changes made to asset: {asset_id}")
            return False
    except Exception as e:
        return handle_database_error("update_asset", e) 
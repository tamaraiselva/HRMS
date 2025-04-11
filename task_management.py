import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List
from db import get_all_employees

def initialize_tasks():
    if 'tasks' not in st.session_state:
        st.session_state.tasks = []

def create_task(assignee: str, title: str, description: str, due_date: str, priority: str) -> Dict:
    return {
        "task_id": len(st.session_state.tasks) + 1,
        "title": title,
        "description": description,
        "assignee": assignee,
        "assigner": st.session_state.current_user["username"],
        "status": "Pending",
        "priority": priority,
        "due_date": due_date,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "comments": []
    }

def add_comment(task_id: int, comment: str) -> None:
    for task in st.session_state.tasks:
        if task["task_id"] == task_id:
            task["comments"].append({
                "user": st.session_state.current_user["username"],
                "comment": comment,
                "timestamp": datetime.now().isoformat()
            })
            task["updated_at"] = datetime.now().isoformat()
            break

def update_task_status(task_id: int, new_status: str) -> None:
    for task in st.session_state.tasks:
        if task["task_id"] == task_id:
            task["status"] = new_status
            task["updated_at"] = datetime.now().isoformat()
            break

def get_user_tasks(username: str) -> List[Dict]:
    return [task for task in st.session_state.tasks if task["assignee"] == username]

def task_management():
    st.header("Task Management")
    
    initialize_tasks()
    
    current_user = st.session_state.current_user
    user_role = current_user["role"]
    username = current_user["username"]
    
    employees = get_all_employees()
    employee_options = [f"{emp['employee_id']} - {emp['name']}" for emp in employees]
    
    with st.expander("Create New Task"):
        with st.form("task_form"):
            title = st.text_input("Task Title")
            description = st.text_area("Task Description")
            assignee = st.selectbox(
                "Assign To",
                employee_options,
                key="task_assignee"
            )
            due_date = st.date_input("Due Date")
            priority = st.selectbox(
                "Priority",
                ["Low", "Medium", "High"],
                key="task_priority"
            )
            
            if st.form_submit_button("Create Task"):
                if not all([title, description, assignee, due_date, priority]):
                    st.error("Please fill in all fields")
                    return

                emp_id = assignee.split(" - ")[0]
                
                new_task = create_task(
                    assignee=emp_id,
                    title=title,
                    description=description,
                    due_date=due_date.isoformat(),
                    priority=priority
                )
                st.session_state.tasks.append(new_task)
                st.success("Task created successfully!")
    
    st.subheader("Task List")
    

    col1, col2 = st.columns(2)
    with col1:
        filter_status = st.selectbox(
            "Filter by Status",
            ["All", "Pending", "In Progress", "Completed"],
            key="task_filter_status"
        )
    with col2:
        if user_role in ["admin", "hr"]:
            filter_assignee = st.selectbox(
                "Filter by Assignee",
                ["All"] + employee_options,
                key="task_filter_assignee"
            )
        else:
            filter_assignee = username
    
    tasks_to_display = st.session_state.tasks
    
    if filter_status != "All":
        tasks_to_display = [task for task in tasks_to_display if task["status"] == filter_status]
    
    if filter_assignee != "All":
        if isinstance(filter_assignee, str) and " - " in filter_assignee:
            emp_id = filter_assignee.split(" - ")[0]
            tasks_to_display = [task for task in tasks_to_display if task["assignee"] == emp_id]
        else:
            tasks_to_display = [task for task in tasks_to_display if task["assignee"] == filter_assignee]
    
    if tasks_to_display:
        for task in tasks_to_display:
            with st.expander(f"Task #{task['task_id']}: {task['title']} ({task['status']})"):
                st.write(f"**Description:** {task['description']}")
                st.write(f"**Assignee:** {task['assignee']}")
                st.write(f"**Priority:** {task['priority']}")
                st.write(f"**Due Date:** {task['due_date']}")
                st.write(f"**Created At:** {task['created_at']}")
                
                if task["assignee"] == username or user_role in ["admin", "hr"]:
                    new_status = st.selectbox(
                        "Update Status",
                        ["Pending", "In Progress", "Completed"],
                        index=["Pending", "In Progress", "Completed"].index(task["status"]),
                        key=f"status_{task['task_id']}"
                    )
                    if new_status != task["status"]:
                        if st.button("Update Status", key=f"update_{task['task_id']}"):
                            update_task_status(task["task_id"], new_status)
                            st.success("Status updated successfully!")
                            st.rerun()
                
                st.subheader("Comments")
                for comment in task["comments"]:
                    st.write(f"**{comment['user']}** ({comment['timestamp']}):")
                    st.write(comment["comment"])
                
                new_comment = st.text_area("Add Comment", key=f"comment_{task['task_id']}")
                if st.button("Add Comment", key=f"add_comment_{task['task_id']}"):
                    if new_comment:
                        add_comment(task["task_id"], new_comment)
                        st.success("Comment added successfully!")
                        st.rerun()
    else:
        st.info("No tasks found matching the current filters.") 
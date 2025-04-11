# HR Management System

A comprehensive Human Resource Management System built with Streamlit and MongoDB, designed to streamline HR operations and employee management.

## Features

### 1. Employee Management
- View and manage employee information in a table format
- Add new employees
- Edit employee details
- Role-based access control (Admin, HR, Employee)
- Employee ID, Name, Department, Position tracking
- Contact information management (Email, Phone)
- Salary and hire date tracking

### 2. Leave Management
- Submit and track leave requests
- Approve/reject leave requests (Admin/HR)
- View leave history
- Different leave types (Annual, Sick, Personal, Other)
- Leave status tracking (Pending, Approved, Rejected)

### 3. Attendance Tracking
- Record daily attendance
- Track attendance status (Present, Absent, Late, Half Day)
- View attendance history
- Add attendance notes
- Filter and search attendance records

### 4. Task Management
- Create and assign tasks
- Track task status (Pending, In Progress, Completed)
- Add task comments
- Set task priorities
- Filter tasks by status and assignee

### 5. Asset Management
- Track company assets
- Assign assets to employees
- Monitor asset status
- Record asset details (Name, Type, Serial Number)

### 6. AI Assistant
- Get AI-powered assistance for HR queries
- Quick answers to common HR questions
- Context-aware responses

## Security Features
- Secure password hashing
- Session timeout
- Login attempt limiting
- Account lockout after multiple failed attempts
- Role-based access control
- Secure session management

## Installation

1. Clone the repository:
```bash
git clone [[repository-url]](https://github.com/tamaraiselva/HRMS)
cd HRMS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
HRMS=your_database_name
GOOGLE_API_KEY=your_google_api_key
```

4. Run the application:
```bash
streamlit run app.py
```

## Default Users

The system comes with a default admin user:
- Username: `admin`
- Password: `Admin@123`

## User Roles

1. **Admin**
   - Full access to all modules
   - Can manage all employees
   - Can approve/reject leave requests
   - Can manage assets
   - Can assign tasks

2. **HR**
   - Access to employee management
   - Can manage leave requests
   - Can track attendance
   - Can assign tasks
   - Can manage assets

3. **Employee**
   - Can view own information
   - Can request leaves
   - Can view assigned tasks
   - Can mark attendance
   - Can view own leave history

## Database Structure

The system uses MongoDB collections:
- `users`: User authentication and roles
- `employees`: Employee information
- `tasks`: Task management
- `leaves`: Leave requests
- `attendance`: Attendance records
- `assets`: Company assets

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact [support-email] or open an issue in the repository. 

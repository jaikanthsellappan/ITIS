
# Secure Library Web Application

## 🧭 Overview

This project is a secure web-based library system developed as part of the IT Infrastructure and Security course. The application is built using **Python Flask** for the backend, **SQLite** for persistent data storage, and includes integrated security mechanisms such as **bcrypt-based password hashing**, **secure token-based password resets**, and **role-based access control** for admin and normal users.

The system supports user registration, authentication, and protected access to downloadable digital resources (books), with full security best practices applied throughout.

---

## Technologies Used

### Backend
- **Flask** (Core Web Framework)
- **Flask-Migrate** (Database migration tool)
- **Flask-SQLAlchemy** (ORM for SQLite)
- **Flask-Login** (User session management)
- **Flask-Mail** (Secure password reset emails)
- **Flask-Bcrypt** (Password hashing)
- **itsdangerous** (Token generation for reset URLs)

### Frontend
- HTML5 / CSS3
- Jinja2 Templating Engine

### Database
- SQLite (`users.db`)

---

## Security Features

- **User Authentication**: Secure login and registration system with hashed passwords (Bcrypt).
- **Validation**: Frontend + backend validations for email format, password strength, and password match.
- **Password Reset**: Time-limited reset tokens (1-hour expiry) using secure URLs sent via email.
- **Authorization Control**:
  - **Normal users**: Limited access to library and personal account.
  - **Admin users**: View all registered users and perform admin-only tasks.
- **Session Security**: Managed by Flask-Login and protected using decorators like `@login_required`.
- **Data Encryption**: HTTPS recommended during deployment for secure transmission.
- **Role-based Access**: Routes are protected based on user roles.
- **Search Filtering & SQL Injection Protection**: Implemented using ORM (SQLAlchemy).

---

## Project Structure

```
ITIS_ASS_3/
├── app.py                # Flask entry point
├── admin.py              # Admin-specific routes and logic
├── instance/
│   └── users.db          # SQLite database
├── migrations/           # DB migration folder (Flask-Migrate)
├── static/
│   └── styles.css        # CSS styling
├── templates/            # HTML templates
│   ├── login.html
│   ├── signup.html
│   ├── users.html
│   ├── home.html
│   ├── admin_dashboard.html
│   ├── reset_password.html
│   └── ...
├── venv/                 # Python virtual environment
├── README.md             # Project documentation
└── requirements.txt      # Python dependency list
```

---

## Installation & Setup

### Prerequisites

Ensure the following are installed:

- Python 3.8+
- pip 20.x+
- (Optional for email) SMTP test account or service like Mailtrap

### Install Dependencies

```bash
pip install flask
pip install Flask-Migrate
pip install Flask-SQLAlchemy
pip install Flask-Login
pip install Flask-Mail
pip install Flask-Bcrypt
```

---

## Running the Application

```bash
python app.py
```

Visit: `http://localhost:5000`

---

## Core Features

-   **User Features**
  - Secure Registration/Login with validation
  - Password Reset with secure token (valid for 1 hour)
  - View and search digital books
  - Download available books securely

-   **Admin Features**
  - View list of all registered users
  - Protected access to admin dashboard

-   **Security Measures**
  - Bcrypt hashing for passwords
  - Token-based password reset
  - Role-based route protection
  - Flash messages for feedback
  - HTTPS-ready for production

---

##   Cryptographic & Protocol Integrations

-  **Diffie-Hellman Key Exchange**
  - Demonstrated for secure key establishment
-  **Digital Signature Example**
  - Illustrates integrity and authenticity of communications using public/private key pairs

---

##   Authors & Team

Team Members:
Jaikanth Sellappan
Rishekesh Baddirappan

---

##   References

1. Grinberg, M. (2018). *Flask Web Development*, 2nd Edition. O'Reilly.
2. Diffie, W., & Hellman, M. (1976). *New Directions in Cryptography*.
3. Rivest, R., Shamir, A., & Adleman, L. (1978). *Public-Key Cryptosystems*.
4. Provos, N., & Mazieres, D. (1999). *Future-Adaptable Password Scheme*.

---

##  Future Improvements

- Add file-based audit logging
- Implement 2FA (two-factor authentication)
- Add book recommendation engine based on user behavior
- Dockerize the app for production deployment

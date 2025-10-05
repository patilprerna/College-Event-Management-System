# College Event Management System

Flask aur MySQL par bana ek College Event Management System. Is project mein admin events create kar sakte hain aur students unke liye register kar sakte hain.

## Features

- User Authentication (Admin & Student roles)
- Admin dwara Events ka CRUD (Create, Read, Update, Delete)
- Events ke liye Student Registration
- Clean aur Responsive UI

## Tech Stack

- Backend: Flask, Flask-SQLAlchemy, Flask-Login
- Database: MySQL
- Frontend: HTML, Bootstrap 5
- Forms: Flask-WTF

## Setup and Installation

Is project ko apne local machine par chalaane ke liye neeche diye gaye steps follow karein:

1.  Repository Clone Karein:
    ```bash
    git clone [aapke_repository_ka_url]
    cd college-event-manager
    ```

2.  Virtual Environment Banayein aur Activate Karein:
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # macOS/Linux
    source venv/bin/activate
    ```

3.  Dependencies Install Karein:
    ```bash
    pip install -r requirements.txt
    ```

4.  Database Setup:
    - MySQL mein `college_events` naam ka ek database banayein.
    - `app.py` file mein `SQLALCHEMY_DATABASE_URI` ko apne MySQL username aur password ke saath update karein.

5.  Application Run Karein:
    ```bash
    flask run
    ```
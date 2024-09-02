TODO Application
Overview
The TODO Application is a web-based application built with FastAPI, SQLAlchemy, and Jinja2. It allows users to manage their tasks with features such as user authentication, task creation, updating, and deletion. The application utilizes a grid layout to display tasks in a user-friendly manner.

Features
User Authentication: Register and log in to manage personal TODOs.
Task Management: Create, update, and delete tasks.
Responsive Design: Tasks are displayed in a grid layout with three items per row.
Installation
Clone the Repository

bash
复制代码
https://github.com/uranbekanarbaev/test_task_Partners-Globalify.git
cd todo-app
Create a Virtual Environment

bash
复制代码
python -m venv venv
Activate the Virtual Environment

On Windows:

bash
复制代码
venv\Scripts\activate
On macOS/Linux:

bash
复制代码
source venv/bin/activate
Install Dependencies

bash
复制代码
pip install -r requirements.txt
Run the Application

bash
复制代码
uvicorn app.main:app --reload
The application will be available at http://127.0.0.1:8000.

Usage
Home Page: Visit http://127.0.0.1:8000 to access the home page and navigate to login, register, or view TODOs.
Login: Use /login to access the login page.
Register: Use /register to access the registration page.
TODOs: After logging in, you can manage TODOs via /todos.
API Endpoints
POST /token: Obtain an access token by providing username and password.
POST /register: Register a new user.
POST /login: Log in and obtain an access token.
POST /logout: Log out by invalidating the access token.
GET /todos/: View all TODO items for the logged-in user.
POST /todos/create: Create a new TODO item.
POST /todos/{todo_id}/update: Update an existing TODO item.
POST /todos/{todo_id}/delete: Delete a TODO item.
HTML Templates
base.html: Base template for layout.
index.html: Welcome page.
login.html: Login form.
register.html: Registration form.
todo.html: TODO management page with grid layout.
CSS Styling
style.css: Contains styles for the TODO application including layout, forms, and buttons.
Contributing
Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature/YourFeature).
Create a new Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.

Contact
For any questions or issues, please contact uranbekanarbnaev@gmail.com.
@uranbekanarbaev - Telegram
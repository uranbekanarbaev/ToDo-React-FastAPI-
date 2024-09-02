import pytest
from httpx import AsyncClient
from fastapi import FastAPI
from backend.main import app  # Adjust the import based on your project structure
from backend.database import SessionLocal, engine, Base
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

# Initialize the FastAPI TestClient
client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    # Create the database tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Drop the database tables
        Base.metadata.drop_all(bind=engine)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Welcome to the TODO app" in response.text  # Adjust this based on your HTML content

def test_register_user(test_db: Session):
    response = client.post("/register", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"

def test_login_user(test_db: Session):
    client.post("/register", data={"username": "testuser", "password": "testpassword"})
    response = client.post("/login", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 302
    assert "access_token" in response.cookies

def test_create_todo(test_db: Session):
    # First, login to get the token
    client.post("/register", data={"username": "testuser", "password": "testpassword"})
    response = client.post("/login", data={"username": "testuser", "password": "testpassword"})
    token = response.cookies["access_token"]

    # Use the token to create a todo item
    response = client.post(
        "/todos/create",
        data={"title": "Test Todo", "description": "Test Description"},
        cookies={"access_token": token}
    )
    assert response.status_code == 200
    assert "Test Todo" in response.text

def test_update_todo(test_db: Session):
    # Register and login user
    client.post("/register", data={"username": "testuser", "password": "testpassword"})
    response = client.post("/login", data={"username": "testuser", "password": "testpassword"})
    token = response.cookies["access_token"]

    # Create a todo item
    client.post(
        "/todos/create",
        data={"title": "Test Todo", "description": "Test Description"},
        cookies={"access_token": token}
    )

    # Update the todo item
    response = client.post(
        "/todos/1/update",
        data={"title": "Updated Todo", "description": "Updated Description", "completed": True},
        cookies={"access_token": token}
    )
    assert response.status_code == 200
    assert "Updated Todo" in response.text

def test_delete_todo(test_db: Session):
    # Register and login user
    client.post("/register", data={"username": "testuser", "password": "testpassword"})
    response = client.post("/login", data={"username": "testuser", "password": "testpassword"})
    token = response.cookies["access_token"]

    # Create a todo item
    client.post(
        "/todos/create",
        data={"title": "Todo to Delete", "description": "Description"},
        cookies={"access_token": token}
    )

    # Delete the todo item
    response = client.post(
        "/todos/1/delete",
        cookies={"access_token": token}
    )
    assert response.status_code == 200
    assert "Todo to Delete" not in response.text


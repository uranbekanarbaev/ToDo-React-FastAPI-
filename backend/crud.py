from sqlalchemy.orm import Session
from backend import models, schemas
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schemas.UserCreate):
    from .auth import get_password_hash
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password) if user.password else None,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user

def get_todo_items(db: Session, user_id: int, skip: int = 0, limit: int = 10):
    return db.query(models.TodoItem).filter(models.TodoItem.owner_id == user_id).offset(skip).limit(limit).all()

def get_todo_item(db: Session, todo_id: int, user_id: int):
    return db.query(models.TodoItem).filter(models.TodoItem.id == todo_id, models.TodoItem.owner_id == user_id).first()

def create_todo_item(db: Session, todo: schemas.TodoItemCreate, user_id: int):
    db_todo = models.TodoItem(**todo.dict(), owner_id=user_id)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo

def update_todo_item(db: Session, todo_id: int, todo: schemas.TodoItemCreate, user_id: int):
    db_todo = db.query(models.TodoItem).filter(models.TodoItem.id == todo_id, models.TodoItem.owner_id == user_id).first()
    db_todo.title = todo.title
    db_todo.description = todo.description
    db_todo.deadline = todo.deadline
    db.commit()
    db.refresh(db_todo)
    return db_todo

def delete_todo_item(db: Session, todo_id: int, user_id: int):
    db_todo = db.query(models.TodoItem).filter(models.TodoItem.id == todo_id, models.TodoItem.owner_id == user_id).first()
    db.delete(db_todo)
    db.commit()
    return db_todo

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

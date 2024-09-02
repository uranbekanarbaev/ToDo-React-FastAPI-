# app/models.py

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Date
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    """
    Represents a user in the system.

    Attributes:
        id (int): The unique identifier for the user.
        username (str): The username of the user.
        email (str): The email address of the user.
        hashed_password (str): The hashed password of the user.

    Relationships:
        todos (relationship): A list of TodoItem instances associated with this user.
    """
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=True)

    todos = relationship("TodoItem", back_populates="owner")


class TodoItem(Base):
    """
    Represents a to-do item.

    Attributes:
        id (int): The unique identifier for the to-do item.
        title (str): The title of the to-do item.
        description (str): The description of the to-do item.
        completed (bool): The completion status of the to-do item.
        owner_id (int): The ID of the user who owns this to-do item.

    Relationships:
        owner (relationship): The User instance associated with this to-do item.
    """
    __tablename__ = "todo_items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    deadline = Column(Date)
    

    owner = relationship("User", back_populates="todos")

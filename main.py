from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import secrets

# Initialize FastAPI
app = FastAPI()

# Database Configuration (MySQL with SQLAlchemy)
DATABASE_URL = "mysql+mysqlconnector://root:@localhost/fastapi_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Initialize Password Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Generate a random 32-character secret key (256 bits)
secret_key = secrets.token_hex(32)

# Define your secret key for JWT
SECRET_KEY = secret_key

# Define the algorithm to be used for JWT
ALGORITHM = "HS256"

# Token expiration time (in minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# SQLAlchemy Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_active = Column(Boolean, default=True)

class ToDoItem(Base):
    __tablename__ = "todo_items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)

Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    username: str
    # Add other fields to update user profile

class UserInDB(BaseModel):
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ToDoItemCreate(BaseModel):
    title: str
    description: str

# Function to create an access token with user data
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to hash a password
def get_password_hash(password):
    return pwd_context.hash(password)

# Authenticate User and Create Access Token
def authenticate_user(db, username, password):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not pwd_context.verify(password, user.password_hash):
        return None
    return user

# Dependency to get the current user
def get_current_user(token: str = Depends(authenticate_user)):
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return UserInDB(username=token.username)

@app.post("/register/", response_model=UserInDB)
async def register_user(user: UserCreate, db: SessionLocal = Depends()):
    db_user = User(username=user.username, password_hash=get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/reset-password/")
async def reset_password(username: str, new_password: str, db: SessionLocal = Depends()):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.password_hash = get_password_hash(new_password)
    db.commit()
    return {"message": "Password reset successful"}

@app.put("/users/me", response_model=UserInDB)
async def update_user_profile(updated_user: UserUpdate, current_user: UserInDB = Depends(get_current_user), db: SessionLocal = Depends()):
    return {"username": updated_user.username}

@app.put("/todos/{todo_id}/", response_model=ToDoItemCreate)
async def update_todo(todo_id: int, updated_todo: ToDoItemCreate, db: SessionLocal = Depends()):
    return {"title": updated_todo.title, "description": updated_todo.description}

@app.delete("/todos/{todo_id}/", response_model=ToDoItemCreate)
async def delete_todo(todo_id: int, db: SessionLocal = Depends()):
    return {"message": "To-Do item deleted successfully"}

@app.post("/todos/", response_model=ToDoItemCreate)
async def create_todo(todo: ToDoItemCreate, db: SessionLocal = Depends()):
    db_todo = ToDoItem(title=todo.title, description=todo.description)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo

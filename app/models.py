from datetime import datetime
from typing import Optional


from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str
    password: Optional[str]


class AuthResponse(BaseModel):
    user: User
    token: str
    expiry: datetime


class AuthRequest(BaseModel):
    username: str
    password: bytes


class Post(BaseModel):
    id: int
    user: User
    content: str
    created_at: datetime
    update_at: datetime


class Comment(BaseModel):
    user: User
    post_id: int
    content: str

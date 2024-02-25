import sqlite3

import bcrypt
from fastapi import HTTPException, status
from config import settings, generate_cookie
from models import AuthRequest, AuthResponse


def create_user(user: AuthRequest, db: sqlite3.Connection) -> AuthResponse:
    salt = bcrypt.gensalt(settings.salt_rounds)
    
    hashed_pwd = bcrypt.kdf(
        user.password, salt,
        settings.pass_length,
        settings.salt_rounds)

    token, expiry = generate_cookie()

    query = """
        INSERT INTO users (username, passhash, token, expiry)
        VALUES (?, ?, ?, ?);
    """

    try:
        cur = db.execute(query, [user.username, hashed_pwd, token, expiry])
        db.commit()
        id = cur.lastrowid

    except sqlite3.IntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=type(e))

    return AuthResponse.model_validate({
        "user": {
            "id": id,
            "username": user.username
        },
        "token": token,
        "expiry": expiry
    })


def login_user(user: AuthRequest) -> AuthResponse:
    
    return AuthResponse.model_validate(

    )
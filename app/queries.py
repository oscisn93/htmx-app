from datetime import datetime
import sqlite3
from typing import Optional


from config import settings, generate_cookie
from models import AuthRequest, AuthResponse
import bcrypt


class InvalidPassword(Exception):
    pass


def create_user(user: AuthRequest, db: sqlite3.Connection) -> Optional[AuthResponse]:
    salt = bcrypt.gensalt(settings.salt_rounds)

    hashed_pwd = bcrypt.kdf(
        user.password, salt, settings.pass_length, settings.salt_rounds
    )

    token, expiry = generate_cookie()

    query = """
        INSERT INTO users (username, passhash, token, expiry)
        VALUES (?, ?, ?, ?);
    """

    try:
        cur = db.execute(query, [user.username, hashed_pwd, token, expiry])
        db.commit()
        id = cur.lastrowid

    except sqlite3.IntegrityError:
        return None

    return AuthResponse.model_validate(
        {
            "user": {"id": id, "username": user.username},
            "token": token,
            "expiry": expiry,
        }
    )


def verify_user(
    username: str, password: str, db: sqlite3.Connection
) -> Optional[AuthResponse]:
    query = """
        SELECT id, username, passhash, token, expiry
        FROM users
        WHERE username = ?;
    """

    row = db.execute(query, [username]).fetchone()

    if row is None:
        return None

    if not bcrypt.checkpw(password, row["passhash"]):
        raise Exception("Invalid password")

    id = row["id"]
    expiry = row["expiry"]

    if datetime.fromisoformat(expiry) > datetime.now():
        # an attempt at automatic retry in case of collision
        while True:
            try:
                token, expiry = generate_cookie()
                query = """
                    UPDATE users
                    SET token = ?,
                        expiry = ?
                    WHERE id = ?;
                """
                db.execute(query, [token, expiry, id])
                db.commit()
                break
            except sqlite3.IntegrityError:
                continue
    else:
        token = row["token"]

    return AuthResponse.model_validate(
        {
            "user": {
                "id": id,
                "username": username,
            },
            "token": token,
            "expiry": expiry,
        }
    )

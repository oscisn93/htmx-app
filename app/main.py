from datetime import datetime, timedelta
import sqlite3
import secrets


from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.staticfiles  import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import bcrypt


from config import get_db


SALT_ROUNDS = 10
PASSHASH_LENGTH = 15


class User(BaseModel):
    id: int
    username: str
    token: str
    expiry: datetime


class AuthRequest(BaseModel):
    username: str
    password: bytes


class Post(BaseModel):
    id: int
    username: int
    content: str
    created_at: datetime
    update_at: datetime


class Comment(BaseModel):
    username: str
    post_id: int
    content: str


def generate_cookie():
    token = secrets.token_urlsafe(16)
    expiry = datetime.now() + timedelta(weeks=1)
    return (token, expiry)


app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/views")


@app.get("/")
def landing_page(req: Request):
    return templates.TemplateResponse(
        request=req,
        name="landing.html"
    )


@app.post("/auth/register/")
def register_user(
        req: AuthRequest, request: Request, res: Response, db: sqlite3.Connection = Depends(get_db)
):
    salt = bcrypt.gensalt(SALT_ROUNDS)
    hashed_pwd = bcrypt.kdf(req.password, salt, PASSHASH_LENGTH, SALT_ROUNDS)
    token, expiry = generate_cookie()

    query = """
        INSERT INTO users (username, passhash, token, expiry)
        VALUES (?, ?, ?, ?);
    """

    try:
        db.execute(query, [req.username, hashed_pwd, token, expiry])
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=type(e))

    res.set_cookie(key="session", value=token)

    return templates.TemplateResponse(request=request, name="home.html", context={"username": req.username })


@app.post("/auth/login/")
def login_user(
    req: AuthRequest, res: Response, db: sqlite3.Connection = Depends(get_db)
):
    query = """
        SELECT id, passhash, token, expiry
        FROM users WHERE username = ?;
    """
    row = db.execute(query, [req.username]).fetchall()[0]
    token = row["token"]
    expiry = row["expiry"]
    if not bcrypt.checkpw(req.password, row["passhash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials provided",
        )

    if datetime.fromisoformat(expiry) > datetime.now():
        token, expiry = generate_cookie()
        query = """
            UPDATE users
            SET token = ?,
                expiry = ?
            WHERE id = ?;
        """
        db.execute(query, [token, expiry, row["id"]])

    res.set_cookie(key="session", value=token)

    return templates.TemplateResponse(request=request, name="home.html", context={"username": req.username })


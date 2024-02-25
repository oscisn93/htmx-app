from datetime import datetime
import sqlite3


from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.staticfiles  import StaticFiles
from fastapi.templating import Jinja2Templates
import bcrypt


from models import AuthRequest, User, Post, Comment
from queries import create_user, login_user
from config import get_db, settings, generate_cookie


app = FastAPI()


app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/")
def landing_page(req: Request):
    return templates.TemplateResponse(
        request=req,
        name="landing.html"
    )


@app.post("/auth/register/")
def register_user(
        req: Request, res: Response, auth: AuthRequest, db: sqlite3.Connection = Depends(get_db)
):
    session = create_user(auth, db)
    res.set_cookie(key="session", value=session.token)

    return templates.TemplateResponse(request=req, name="home.html", context={"username": session.username })


@app.post("/auth/login/")
def login_user(
    req: AuthRequest, request: Request, res: Response, db: sqlite3.Connection = Depends(get_db)
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


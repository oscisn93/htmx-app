import sqlite3


from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


from models import AuthRequest
from queries import InvalidPassword, create_user, verify_user
from config import get_db


app = FastAPI()


app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/")
def landing_page(req: Request):
    return templates.TemplateResponse(request=req, name="landing.html")


@app.post("/auth/register/")
def register_user(
    req: Request,
    res: Response,
    auth: AuthRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    session = create_user(auth, db)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username already exists"
        )

    res.set_cookie(key="session", value=session.token)

    return templates.TemplateResponse(
        request=req, name="home.html", context={"username": session.user.username}
    )


@app.post("/auth/login/")
def login_user(
    req: AuthRequest,
    request: Request,
    res: Response,
    db: sqlite3.Connection = Depends(get_db),
):
    try:
        userSession = verify_user(req.username, req.password, db)
    except InvalidPassword:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )
    if userSession is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    res.set_cookie(key="session", value=userSession.token)

    return templates.TemplateResponse(
        request=request, name="home.html", context={"username": userSession.username}
    )


@app.get("/auth/logout/")
def logout_user(req: Request, res: Response):
    res.delete_cookie(key="session")
    return templates.TemplateResponse(
        name="landing.html", context={"request": req}
    )
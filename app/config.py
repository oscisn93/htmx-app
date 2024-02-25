from contextlib import closing
from datetime import datetime, timedelta
import secrets
import sqlite3


from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database: str
    pass_length: int
    salt_rounds: int
    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()


def get_db():
    with closing(sqlite3.connect(settings.database)) as db:
        db.row_factory = sqlite3.Row
        yield db


def generate_cookie():
    token = secrets.token_urlsafe(16)
    expiry = datetime.now() + timedelta(days=7)
    return (token, expiry)

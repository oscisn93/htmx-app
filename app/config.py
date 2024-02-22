from contextlib import closing
import sqlite3


from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database: str
    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()


def get_db():
    with closing(sqlite3.connect(settings.database)) as db:
        db.row_factory = sqlite3.Row
        yield db

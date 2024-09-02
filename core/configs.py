from sqlalchemy.ext.declarative import declarative_base
from pydantic_settings import BaseSettings
from typing import ClassVar
import os


class Settings(BaseSettings):
    """
    Configurações gerais da aplicação.
    """
    API_V1_STR: str = '/api/v1'
    database_url: str = os.getenv("DATABASE_URL")
    DBBaseModel: ClassVar = declarative_base()
    JWT_SECRET: str = os.getenv("JWT_SECRET")

    '''
    import secrets
    token: str = secrets.token_urlsafe(32)
    token
    
    '''
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    class Config:
        case_sensitive = True


settings = Settings()

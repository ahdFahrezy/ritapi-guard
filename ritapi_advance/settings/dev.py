from .base import *  # noqa
import os

DEBUG = True
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

# DB untuk dev pakai sqlite
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "db_ritapi_advance"),
        "USER": os.getenv("POSTGRES_USER", "postgres"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

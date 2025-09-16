# config/settings/prod.py
from .base import *  # noqa
import os

# === Security ===
DEBUG = False
SECRET_KEY = os.getenv("SECRET_KEY")  # wajib ada di .env.prod
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "ritapi.example.com").split(",")
ALLOW_IPS = os.getenv("ALLOW_IPS", "127.0.0.1").split(",")
ALLOW_IPS = [ip.strip() for ip in ALLOW_IPS if ip.strip()]

# === Database (Postgres in Production) ===
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "ritapi"),
        "USER": os.getenv("POSTGRES_USER", "ritapi"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

# === Static & Media Files ===
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# === Security Headers ===
# SECURE_SSL_REDIRECT = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_HSTS_SECONDS = 31536000  # 1 year
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True
# SECURE_BROWSER_XSS_FILTER = True
# SECURE_CONTENT_TYPE_NOSNIFF = True

# === Email (override untuk prod) ===
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False") == "True"
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "alerts@ritapi.example.com")

# === Logging (bawa semua yang ada di base, tapi bisa override kalau perlu) ===
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "detailed": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/train_iforest.log",
            "formatter": "detailed",
        },
        "file_tls": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/tls_analyzer.log",
            "formatter": "detailed",
        },
        "file_decision": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/decision_engine.log",
            "formatter": "detailed",
        },
    },
    "loggers": {
        "ai_behaviour": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "tls_analyzer": {
            "handlers": ["console", "file_tls"],
            "level": "DEBUG",
            "propagate": False,
        },
        "decision_engine": {
            "handlers": ["console", "file_decision"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

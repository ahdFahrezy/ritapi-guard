# config/settings/__init__.py
import os
env = os.getenv("DJANGO_ENV", "dev")
if env == "prod":
    from .prod import *   # noqa
else:
    from .dev import *    # noqa
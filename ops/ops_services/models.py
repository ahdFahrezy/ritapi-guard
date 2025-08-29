import uuid
from django.db import models

class Service(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    target_base_url = models.URLField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.target_base_url} ({self.uuid})"
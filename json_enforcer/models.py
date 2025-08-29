from django.db import models
from ops.ops_services.models import Service  # import model Service

class JsonSchema(models.Model):
    service = models.ForeignKey(
        Service,
        to_field="uuid",
        db_column="service_uuid",
        on_delete=models.CASCADE,
        related_name="json_schemas",
        null=True,   # <---- tambahkan ini
        blank=True   # <---- biar form admin juga ga wajib
    )

    name = models.CharField(max_length=100)
    endpoint = models.CharField(max_length=255)
    schema_json = models.JSONField()
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} → {self.service.target_base_url}"

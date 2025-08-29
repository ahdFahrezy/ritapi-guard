from django.db import models
from django.utils import timezone


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    alert_type = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    detail = models.TextField()
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default="low"
    )
    resolved = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity.upper()}] {self.alert_type} - {self.ip_address}"


class BlockedIP(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default="low"
    )
    blocked_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)   # ⬅️ untuk durasi blokir
    active = models.BooleanField(default=True)

    def __str__(self):
        return f"[{self.severity.upper()}] {self.ip_address}"

    def is_active(self):
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return self.active

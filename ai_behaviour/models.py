from django.db import models
from django.utils import timezone


class BehaviourLogs(models.Model):
    endpoint = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    method = models.CharField(max_length=10)
    payload_size = models.IntegerField()
    user_agent = models.CharField(max_length=255)
    status_code = models.IntegerField()
    response_time_ms = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.endpoint} - {self.ip_address}"


class BehaviourAnomaly(models.Model):
    DETECTED_BY_CHOICES = [
        ("rule", "Rule-Based"),
        ("ml", "IsolationForest"),
    ]

    log = models.ForeignKey(BehaviourLogs, on_delete=models.CASCADE, related_name="anomalies")
    ip_address = models.GenericIPAddressField()
    anomaly_type = models.CharField(max_length=100)  # contoh: "High Entropy Payload", "Unusual Frequency"
    risk_score = models.FloatField()
    detected_at = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    detected_by = models.CharField(max_length=20, choices=DETECTED_BY_CHOICES, default="rule")

    def __str__(self):
        return f"{self.anomaly_type} ({self.ip_address})"

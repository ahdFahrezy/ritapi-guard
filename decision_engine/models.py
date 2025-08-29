from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    path = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    body_size = models.IntegerField()
    score = models.FloatField()
    decision = models.CharField(max_length=20)   # "allow" | "block"
    reason = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.decision.upper()}] {self.ip_address} {self.path} ({self.score})"

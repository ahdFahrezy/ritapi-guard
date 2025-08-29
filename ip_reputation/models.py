from django.db import models

class IpReputation(models.Model):
    ip_address = models.GenericIPAddressField()
    scores = models.JSONField()  # detail breakdown
    reputation_score = models.FloatField()  # final score
    isp = models.CharField(max_length=255, null=True, blank=True)  # opsional
    country = models.CharField(max_length=50, null=True, blank=True)  # opsional
    is_tor = models.BooleanField(default=False)  # opsional
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.reputation_score}"

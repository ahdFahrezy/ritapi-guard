from django.db import models
from tls_analyzer.models import TlsAnalyzer

class AsnInfo(models.Model):
    ip_address = models.GenericIPAddressField()
    asn_number = models.CharField(max_length=50)
    trust_score = models.FloatField()
    asn_description = models.TextField(null=True, blank=True)  
    timestamp = models.DateTimeField(auto_now_add=True)
    is_latest = models.BooleanField(default=True)

    def __str__(self):
        return f"ASN {self.asn_number} - {self.ip_address}"
    class Meta:
        indexes = [
            models.Index(fields=["ip_address", "is_latest"]),  # 🔹 untuk query cepat
        ]


class AsnTrustConfig(models.Model):
    asn_number = models.CharField(max_length=50, unique=True)   # contoh: "AS15169"
    name = models.CharField(max_length=100)                     # contoh: "Google"
    score = models.FloatField(default=0)                        # nilai trust score
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.asn_number} - {self.name} ({self.score})"
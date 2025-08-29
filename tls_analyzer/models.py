from django.db import models


class TlsAnalyzer(models.Model):
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255)
    subject = models.TextField()  # ganti CharField → TextField biar tidak kepotong
    issuer = models.TextField()   # sama
    expires = models.DateTimeField()
    serial_number = models.CharField(max_length=255)
    is_valid = models.BooleanField(default=True)
    last_checked = models.DateTimeField(auto_now_add=True)  # baru
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

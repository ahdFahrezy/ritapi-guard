from django.contrib import admin
from .models import TlsAnalyzer

@admin.register(TlsAnalyzer)
class TlsAnalyzerAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "hostname", "subject", "issuer", "is_valid", "expires", "timestamp")
    search_fields = ("ip_address", "hostname", "subject", "issuer")
    list_filter = ("is_valid", "expires")

from django.contrib import admin
from .models import AsnInfo, AsnTrustConfig

@admin.register(AsnInfo)
class AsnInfoAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "asn_number", "trust_score", "timestamp")
    search_fields = ("ip_address", "asn_number")
    list_filter = ("trust_score",)


@admin.register(AsnTrustConfig)
class AsnTrustConfigAdmin(admin.ModelAdmin):
    list_display = ("asn_number", "name", "score", "updated_at")
    search_fields = ("asn_number", "name")
    list_filter = ("score",)
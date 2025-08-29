from django.contrib import admin
from .models import IpReputation

@admin.register(IpReputation)
class IpReputationAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "reputation_score", "timestamp")
    search_fields = ("ip_address",)
    list_filter = ("reputation_score",)

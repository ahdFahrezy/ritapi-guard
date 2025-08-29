from django.contrib import admin
from .models import BehaviourLogs, BehaviourAnomaly

@admin.register(BehaviourLogs)
class BehaviourLogsAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "ip_address", "method", "status_code", "response_time_ms", "timestamp")
    search_fields = ("endpoint", "ip_address", "user_agent")
    list_filter = ("method", "status_code")


@admin.register(BehaviourAnomaly)
class BehaviourAnomalyAdmin(admin.ModelAdmin):
    list_display = ("anomaly_type", "ip_address", "risk_score", "resolved", "detected_at", "timestamp")
    search_fields = ("anomaly_type", "ip_address")
    list_filter = ("anomaly_type", "resolved")

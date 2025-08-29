from django.contrib import admin
from .models import RequestLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "ip_address", "method", "path", "score", "decision", "reason", "body_size")
    search_fields = ("ip_address", "path", "reason")
    list_filter = ("decision",)
    ordering = ("-timestamp",)

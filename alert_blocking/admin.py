from django.contrib import admin
from django.utils.html import format_html
from .models import Alert, BlockedIP


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "ip_address", "colored_severity", "resolved", "timestamp")
    search_fields = ("alert_type", "ip_address", "detail")
    list_filter = ("severity", "resolved")
    actions = ["mark_as_resolved"]

    def colored_severity(self, obj):
        color_map = {
            "critical": "red",
            "high": "darkorange",
            "medium": "blue",
            "low": "green",
        }
        color = color_map.get(obj.severity, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_severity_display(),
        )
    colored_severity.short_description = "Severity"

    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(resolved=True)
        self.message_user(request, f"{updated} alert(s) marked as resolved.")
    mark_as_resolved.short_description = "Mark selected alerts as resolved"


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "severity", "status_colored", "blocked_at", "expires_at")
    search_fields = ("ip_address", "reason")
    list_filter = ("severity", "active")
    actions = ["unblock_ips"]

    def status_colored(self, obj):
        if obj.active:
            return format_html('<span style="color: red; font-weight: bold;">Blocked</span>')
        return format_html('<span style="color: green; font-weight: bold;">Unblocked</span>')
    status_colored.short_description = "Status"

    def unblock_ips(self, request, queryset):
        updated = queryset.update(active=False)
        self.message_user(request, f"{updated} IP(s) successfully unblocked.")
    unblock_ips.short_description = "Unblock selected IPs"

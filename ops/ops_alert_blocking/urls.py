from django.urls import path
from . import views

urlpatterns = [
    # ALERTS
    path("alert", views.alert_dashboard, name="ops.ops_alert"),
    path("alert/resolve/<int:alert_id>/", views.resolve_alert, name="ops_resolve_alert"),
    path("alert/block/<str:ip_address>/", views.block_ip_from_alert, name="ops_block_ip_from_alert"),

    # BLOCKED IPs
    path("alert/blocked-ips/", views.blocked_ip_dashboard, name="ops_blocked_ip_dashboard"),
    path("alert/blocked-ips/unblock/<str:ip_address>/", views.unblock_ip, name="ops_unblock_ip"),
    path("alert/blocked-ips/block/<str:ip_address>/", views.block_ip_manual, name="ops_block_ip_manual"),
]

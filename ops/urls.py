from django.urls import path, include
from . import views

urlpatterns = [
    path("", views.dashboard, name="ops_dashboard"),
    path("tls", include("ops.ops_tls.urls")),
    path("ip-reputation", include("ops.ops_ip_reputation.urls")),
    path("", include("ops.ops_json_schema.urls")),
    path("", include("ops.ops_alert_blocking.urls")),
    path("", include("ops.ops_asn_score.urls")),
    path("", include("ops.ops_services.urls")),
        # License Management
    path("license/", include("ops.ops_license_manager.urls")),
    path("requestlogs/", include("ops.ops_logs.urls")),

    # path("tls/", views.tls_check, name="ops_tls"),
    # path("ip-reputation/", views.ip_reputation, name="ops_ip_reputation"),
    # path("request-log/", views.request_log, name="ops_request_log"),
    # path("alerts/", views.alert_list, name="ops_alerts"),
    # path("blocking/", views.blocking, name="ops_blocking"),
]

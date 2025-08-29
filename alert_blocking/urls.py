from django.urls import path
from .views import (
    CreateAlertView,
    BlockIPView,
    UnblockIPView,
    CheckIPView,
    ListAlertsView,
    ListBlockedIPsView,
)

urlpatterns = [
    path("alert/", CreateAlertView.as_view(), name="create-alert"),
    path("alerts/", ListAlertsView.as_view(), name="list-alerts"),
    path("block/", BlockIPView.as_view(), name="block-ip"),
    path("unblock/", UnblockIPView.as_view(), name="unblock-ip"),
    path("check/<str:ip_address>/", CheckIPView.as_view(), name="check-ip"),
    path("blocked/", ListBlockedIPsView.as_view(), name="list-blocked"),
]

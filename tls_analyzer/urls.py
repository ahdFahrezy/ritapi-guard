from django.urls import path
from .views import TlsCheckView, TlsHistoryView

urlpatterns = [
    path("check/", TlsCheckView.as_view(), name="tls-check"),
    path("history/", TlsHistoryView.as_view(), name="tls-history"),
]

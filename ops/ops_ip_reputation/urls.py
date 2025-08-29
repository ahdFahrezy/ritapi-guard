from django.urls import path
from . import views

urlpatterns = [
    path("", views.ip_reputation_dashboard, name="ops_ip_reputation_check"),
]

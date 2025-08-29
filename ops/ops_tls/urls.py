from django.urls import path
from . import views

urlpatterns = [
    path("", views.tls_dashboard, name="ops_tls"),
    path("check/", views.tls_check_new, name="ops_tls_check_new"),
]

from django.urls import path
from . import views

urlpatterns = [
    path("asn-checker/", views.asn_checker, name="ops_asn_checker"),
    path("asn-update-score/", views.asn_update_score, name="ops_asn_update_score"),
]

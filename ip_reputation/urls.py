from django.urls import path
from .views import IpReputationLookupView

urlpatterns = [
    path("lookup/", IpReputationLookupView.as_view(), name="ip-reputation-lookup"),
]

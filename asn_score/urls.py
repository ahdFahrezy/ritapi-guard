from django.urls import path
from .views import AsnLookupView, AsnHistoryView

urlpatterns = [
    path("lookup/", AsnLookupView.as_view(), name="asn-lookup"),
    path("history/", AsnHistoryView.as_view(), name="asn-history"),
]
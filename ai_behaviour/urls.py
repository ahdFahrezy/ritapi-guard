from django.urls import path
from .views import BehaviourLogView, AnomalyListView

urlpatterns = [
    path("log/", BehaviourLogView.as_view(), name="behaviour-log"),
    path("anomalies/", AnomalyListView.as_view(), name="behaviour-anomalies"),
]

from django.urls import path
from .views import JsonValidateView

urlpatterns = [
    path("validate/", JsonValidateView.as_view(), name="json-validate"),
]

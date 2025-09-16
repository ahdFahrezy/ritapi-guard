# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.requestlog_list, name="requestlog_list"),
    path("export/", views.export_requestlog_excel, name="export_requestlog_excel"),
    path("api/", views.requestlog_data, name="requestlog_data"),
]
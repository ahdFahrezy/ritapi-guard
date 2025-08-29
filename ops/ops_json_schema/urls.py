# ops/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("json-enforcer", views.jsonschema_dashboard, name="ops.jsonschema_dashboard"),
    path("json-enforcer/create/", views.jsonschema_create, name="jsonschema_create"),
    path("json-enforcer/update/<int:pk>/", views.jsonschema_update, name="jsonschema_update"),
    path("json-enforcer/delete/<int:pk>/", views.jsonschema_delete, name="jsonschema_delete"),
    path("json-enforcer/toggle/<int:pk>/", views.jsonschema_toggle, name="jsonschema_toggle"),
]
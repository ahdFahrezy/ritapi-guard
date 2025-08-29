from django.urls import path
from . import views

app_name = 'ops_license_manager'

urlpatterns = [
    # Web views
    path('activate/', views.license_activate_view, name='activate'),
    path('status/', views.license_status_view, name='status'),
    
    # API endpoints
    path('api/activate/', views.api_activate_license, name='api_activate'),
    path('api/status/', views.api_license_status, name='api_status'),
    path('api/deactivate/', views.api_deactivate_license, name='api_deactivate'),
    path('api/health/', views.health_check, name='api_health'),
    
    # Default redirect
    path('', views.license_activate_view, name='index'),
]

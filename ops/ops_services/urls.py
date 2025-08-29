from django.urls import path
from . import views

app_name = 'ops_services'

urlpatterns = [
    # Dashboard view - accessible from main ops URLs
    path('services/', views.service_dashboard, name='service_dashboard'),
    
    # Service detail view
    path('services/<uuid:service_uuid>/', views.service_detail_view, name='service_detail'),
    
    # API endpoints for service management (required for modals)
    path('api/services/', views.ServiceListView.as_view(), name='service_list_api'),
    path('api/services/<uuid:service_uuid>/', views.ServiceDetailView.as_view(), name='service_detail_api'),
    
    # Health check and status
    path('api/status/', views.service_status, name='service_status'),
]

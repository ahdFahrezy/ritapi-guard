import os
from django.conf import settings
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from django.core.exceptions import ValidationError
from .models import Service
import json
import uuid
import logging

logger = logging.getLogger(__name__)


@login_required
def service_dashboard(request):
    """Dashboard view untuk mengelola service dengan search dan pagination"""
    try:
        # Get search parameter
        search_query = request.GET.get('search', '')
        
        # Ambil konfigurasi dari env
        max_services = int(os.getenv("MAX_SERVICES", 10))  # default 10
        
        # Filter services based on search
        if search_query:
            services = Service.objects.filter(
                target_base_url__icontains=search_query
            ).order_by('timestamp')[:max_services]  # urutkan paling lama & batasi
        else:
            services = Service.objects.all().order_by('timestamp')[:max_services]
        
        # Pagination
        paginator = Paginator(services, 10)  # sesuaikan jumlah per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get total count for statistics
        total_services = services.count() if hasattr(services, "count") else len(services)
        
        context = {
            'services': page_obj if page_obj else services,
            'page_obj': page_obj,
            'total_services': total_services,
            'search_query': search_query,
            'page_title': 'Service Management Dashboard'
        }
        
        return render(request, 'ops/service_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error displaying service dashboard: {e}")
        return render(request, 'ops/service_dashboard.html', {
            'services': [],
            'total_services': 0,
            'page_title': 'Service Management Dashboard'
        })


@login_required
def service_detail_view(request, service_uuid):
    """View untuk menampilkan detail service"""
    try:
        service = get_object_or_404(Service, uuid=service_uuid)
        
        context = {
            'service': service,
            'page_title': f'Service Detail - {service.target_base_url}'
        }
        
        return render(request, 'ops/service_detail.html', context)
        
    except Service.DoesNotExist:
        # Redirect to dashboard if service not found
        return redirect('ops_services:service_dashboard')
    except Exception as e:
        logger.error(f"Error displaying service detail {service_uuid}: {e}")
        return redirect('ops_services:service_dashboard')


@method_decorator([csrf_exempt, login_required], name='dispatch')
class ServiceListView(View):
    """View untuk menampilkan daftar semua service yang tersedia"""
    
    def get(self, request):
        """GET: List semua service"""
        try:
            services = Service.objects.all().order_by('-timestamp')
            service_list = []
            
            for service in services:
                service_list.append({
                    'uuid': str(service.uuid),
                    'target_base_url': service.target_base_url,
                    'timestamp': service.timestamp.isoformat(),
                    'status': 'active'
                })
            
            return JsonResponse({
                'status': 'success',
                'count': len(service_list),
                'services': service_list
            })
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    def post(self, request):
        """POST: Create service baru"""
        try:
            data = json.loads(request.body)
            target_url = data.get('target_base_url')
            
            if not target_url:
                return JsonResponse({
                    'status': 'error',
                    'message': 'target_base_url is required'
                }, status=400)
                
            try:
                max_services = int(os.getenv("MAX_SERVICES", 10))
            except ValueError:
                max_services = 10
            
            # Cek jumlah service di DB
            current_count = Service.objects.count()
            if current_count >= max_services:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Maximum number of services ({max_services}) reached. Cannot add more.'
                }, status=400)
            
            # Validate URL format
            try:
                from django.core.validators import URLValidator
                validator = URLValidator()
                validator(target_url)
            except ValidationError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid URL format'
                }, status=400)
            
            # Create service
            service = Service.objects.create(target_base_url=target_url)
            
            return JsonResponse({
                'status': 'success',
                'message': 'Service created successfully',
                'service': {
                    'uuid': str(service.uuid),
                    'target_base_url': service.target_base_url,
                    'timestamp': service.timestamp.isoformat()
                }
            }, status=201)
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON format'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@method_decorator([csrf_exempt, login_required], name='dispatch')
class ServiceDetailView(View):
    """View untuk detail, update, dan delete service"""
    
    def get(self, request, service_uuid):
        """GET: Detail service berdasarkan UUID"""
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            
            return JsonResponse({
                'status': 'success',
                'service': {
                    'uuid': str(service.uuid),
                    'target_base_url': service.target_base_url,
                    'timestamp': service.timestamp.isoformat()
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    def put(self, request, service_uuid):
        """PUT: Update service"""
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            data = json.loads(request.body)
            target_url = data.get('target_base_url')
            
            if not target_url:
                return JsonResponse({
                    'status': 'error',
                    'message': 'target_base_url is required'
                }, status=400)
            
            # Validate URL format
            try:
                from django.core.validators import URLValidator
                validator = URLValidator()
                validator(target_url)
            except ValidationError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid URL format'
                }, status=400)
            
            # Update service
            service.target_base_url = target_url
            service.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Service updated successfully',
                'service': {
                    'uuid': str(service.uuid),
                    'target_base_url': service.target_base_url,
                    'timestamp': service.timestamp.isoformat()
                }
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON format'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    def delete(self, request, service_uuid):
        """DELETE: Hapus service"""
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            service.delete()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Service deleted successfully'
            })
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@require_http_methods(["GET"])
def service_status(request):
    """Endpoint untuk health check dan status service"""
    try:
        total_services = Service.objects.count()
        active_services = Service.objects.filter(target_base_url__isnull=False).count()
        
        return JsonResponse({
            'status': 'healthy',
            'timestamp': '2024-01-01T00:00:00Z',  # You can make this dynamic
            'services': {
                'total': total_services,
                'active': active_services
            },
            'waf': {
                'status': 'operational',
                'version': '1.0.0'
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'unhealthy',
            'error': str(e)
        }, status=500)


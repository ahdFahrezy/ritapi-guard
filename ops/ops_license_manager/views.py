import json
import logging
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.conf import settings
from .services import LicenseManager
from .models import License, SystemStatus

logger = logging.getLogger(__name__)


def license_activate_view(request):
    """
    View untuk halaman aktivasi license
    """
    license_manager = LicenseManager()
    
    # Cek apakah sistem sudah berlisensi
    is_licensed = license_manager.is_system_licensed()
    current_license_info = license_manager.get_current_license_info()
    
    context = {
        'is_licensed': is_licensed,
        'current_license': current_license_info,
        'page_title': 'License Activation',
    }
    
    if request.method == 'POST':
        serial_number = request.POST.get('serial_number', '').strip()
        
        if not serial_number:
            messages.error(request, 'Please enter a valid serial number.')
            return render(request, 'ops_license_manager/activate.html', context)
        
        # Validate serial number format (XXXX-XXXX-XXXX-XXXX)
        if not _validate_serial_number_format(serial_number):
            messages.error(request, 'Invalid serial number format. Please use format: XXXX-XXXX-XXXX-XXXX')
            return render(request, 'ops_license_manager/activate.html', context)
        
        # Attempt activation
        result = license_manager.activate_system_license(serial_number)
        print(result)
        if result['success']:
            messages.success(request, 'License activated successfully!')
            logger.info(f"License activated successfully via web: {serial_number}")
            
            # Redirect to dashboard or home page after successful activation
            next_url = request.GET.get('next', '/')
            return redirect(next_url)
        else:
            error_message = result.get('message', 'Activation failed')
            error_code = result.get('error_code', 'UNKNOWN')
            
            # Customize error messages for better user experience
            if error_code == 'ALREADY_ACTIVATED':
                messages.warning(request, 'This license is already activated.')
            elif error_code == 'SERIAL_NOT_FOUND':
                messages.error(request, 'Serial number not found. Please check your serial number.')
            elif error_code == 'API_UNAVAILABLE':
                messages.error(request, 'License activation service is currently unavailable. Please try again later.')
            else:
                messages.error(request, f'Activation failed: {error_message}')
            
            logger.warning(f"License activation failed via web: {serial_number} - {error_message}")
    
    return render(request, 'ops_license_manager/activate.html', context)


def license_status_view(request):
    """
    View untuk melihat status license saat ini
    """
    license_manager = LicenseManager()
    
    # Get current license status
    license_status = license_manager.check_system_license_status()
    current_license_info = license_manager.get_current_license_info()
    
    # Get all license records for admin view
    all_licenses = License.objects.all().order_by('-created_at')
    
    context = {
        'license_status': license_status,
        'current_license': current_license_info,
        'all_licenses': all_licenses,
        'page_title': 'License Status',
    }
    
    return render(request, 'ops_license_manager/status.html', context)


@csrf_exempt
@require_http_methods(["POST"])
def api_activate_license(request):
    """
    API endpoint untuk aktivasi license
    """
    try:
        # Parse JSON body
        try:
            data = json.loads(request.body)
            serial_number = data.get('serial_number', '').strip()
        except json.JSONDecodeError:
            # Fallback to form data
            serial_number = request.POST.get('serial_number', '').strip()
        
        if not serial_number:
            return JsonResponse({
                'success': False,
                'message': 'Serial number is required',
                'error_code': 'MISSING_SERIAL'
            }, status=400)
        
        # Validate format
        if not _validate_serial_number_format(serial_number):
            return JsonResponse({
                'success': False,
                'message': 'Invalid serial number format',
                'error_code': 'INVALID_FORMAT'
            }, status=400)
        
        # Activate license
        license_manager = LicenseManager()
        result = license_manager.activate_system_license(serial_number)
        
        if result['success']:
            logger.info(f"License activated successfully via API: {serial_number}")
            return JsonResponse({
                'success': True,
                'message': 'License activated successfully',
                'data': {
                    'serial_number': result['license'].serial_number,
                    'activation_status': result['license'].activation_status,
                    'activated_time': result['license'].activated_time.isoformat() if result['license'].activated_time else None
                }
            })
        else:
            logger.warning(f"License activation failed via API: {serial_number} - {result.get('message')}")
            return JsonResponse({
                'success': False,
                'message': result.get('message', 'Activation failed'),
                'error_code': result.get('error_code', 'ACTIVATION_FAILED')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error in API license activation: {e}")
        return JsonResponse({
            'success': False,
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }, status=500)


@require_http_methods(["GET"])
def api_license_status(request):
    """
    API endpoint untuk cek status license
    """
    try:
        license_manager = LicenseManager()
        
        # Get current license status
        license_status = license_manager.check_system_license_status()
        current_license_info = license_manager.get_current_license_info()
        
        response_data = {
            'success': True,
            'is_licensed': license_status.get('is_licensed', False),
            'message': license_status.get('message', 'Status checked'),
            'data': current_license_info
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Error in API license status check: {e}")
        return JsonResponse({
            'success': False,
            'message': 'Failed to check license status',
            'error_code': 'STATUS_CHECK_ERROR'
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_deactivate_license(request):
    """
    API endpoint untuk deaktivasi license (admin only)
    """
    try:
        # Simple admin check - you can enhance this
        if not request.user.is_authenticated or not request.user.is_staff:
            return JsonResponse({
                'success': False,
                'message': 'Admin access required',
                'error_code': 'ACCESS_DENIED'
            }, status=403)
        
        # Deactivate current license
        system_status = SystemStatus.get_instance()
        if system_status.current_license:
            system_status.current_license.mark_deactivated()
            system_status.update_license_status(None)
            
            logger.info(f"License deactivated by admin: {request.user.username}")
            return JsonResponse({
                'success': True,
                'message': 'License deactivated successfully'
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'No active license found',
                'error_code': 'NO_ACTIVE_LICENSE'
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error in API license deactivation: {e}")
        return JsonResponse({
            'success': False,
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }, status=500)


def health_check(request):
    """
    Simple health check endpoint
    """
    return JsonResponse({
        'status': 'healthy',
        'service': 'license_manager',
        'timestamp': timezone.now().isoformat()
    })


def _validate_serial_number_format(serial_number):
    """
    Validate serial number format: XXXX-XXXX-XXXX-XXXX
    """
    import re
    pattern = r'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'
    return bool(re.match(pattern, serial_number.upper()))


# Import timezone for health check
from django.utils import timezone

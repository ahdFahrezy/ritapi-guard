import logging
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .services import LicenseManager

logger = logging.getLogger(__name__)


class LicenseCheckMiddleware(MiddlewareMixin):
    """
    Middleware untuk mengecek license activation sebelum mengakses sistem.
    Jika sistem belum berlisensi, redirect ke halaman aktivasi license.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.license_manager = LicenseManager()
        
        # URLs yang dikecualikan dari pengecekan license
        self.excluded_paths = [
            '/ops/license/',
            '/ops/license/activate/',
            '/ops/license/status/',
            '/ops/license/api/',
            '/admin/',
            '/static/',
            '/media/',
            '/__debug__/',
            '/health/',
            '/favicon.ico'
        ]
        
        # URLs untuk API yang memerlukan response JSON
        self.api_paths = [
            '/api/',
            '/decision_engine/',  # Jika ada endpoint API di decision engine
        ]
    
    def process_request(self, request):
        """
        Process setiap request untuk mengecek license
        """
        path = request.get_full_path()
        
        # Skip pengecekan untuk path yang dikecualikan
        if self._is_excluded_path(path):
            logger.debug(f"Skipping license check for excluded path: {path}")
            return None
        
        # Skip jika dalam mode development/debug tanpa license check
        if getattr(settings, 'SKIP_LICENSE_CHECK', False):
            return None
        
        # Cek status license sistem
        try:
            is_licensed = self.license_manager.is_system_licensed()
            logger.debug(f"License check for {path}: is_licensed={is_licensed}")
            
            if not is_licensed:
                # Prevent redirect loop - don't redirect if already going to license pages
                if path.startswith('/ops/license/'):
                    logger.warning(f"Already on license page {path} but system not licensed")
                    return None
                
                logger.info(f"Redirecting unlicensed access from {path} to license activation")
                return redirect('/ops/license/activate/')
                    
        except Exception as e:
            logger.error(f"Error checking license in middleware: {e}")
            
            # Dalam kasus error, allow request tapi log error
            if getattr(settings, 'LICENSE_CHECK_FAIL_OPEN', True):
                return None
            else:
                # Strict mode: block jika ada error
                if self._is_api_request(request, path):
                    return JsonResponse({
                        "error": "License check failed",
                        "detail": "Unable to verify system license",
                        "error_code": "LICENSE_CHECK_ERROR"
                    }, status=503)
                else:
                    # Prevent redirect loop
                    if path.startswith('/ops/license/'):
                        return None
                    return redirect('/ops/license/activate/')
        
        return None
    
    def _is_excluded_path(self, path):
        """
        Cek apakah path dikecualikan dari pengecekan license
        """
        # Check exact path matches first
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                logger.debug(f"Path {path} matched excluded pattern {excluded}")
                return True
        
        # Additional safety check for license pages
        if '/license/' in path:
            logger.debug(f"Path {path} contains /license/ - allowing")
            return True
            
        return False
    
    def _is_api_request(self, request, path):
        """
        Determine if this is an API request that should get JSON response
        """
        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return True
        
        # Check if Accept header prefers JSON
        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header and 'text/html' not in accept_header:
            return True
        
        # Check if path starts with API paths
        for api_path in self.api_paths:
            if path.startswith(api_path):
                return True
        
        return False
    
    def process_response(self, request, response):
        """
        Process response to add license information headers
        """
        try:
            # Add license status to response headers for debugging
            if getattr(settings, 'DEBUG', False):
                is_licensed = self.license_manager.is_system_licensed()
                response['X-License-Status'] = 'active' if is_licensed else 'inactive'
                
                # Add license info if available
                license_info = self.license_manager.get_current_license_info()
                if license_info:
                    response['X-License-Serial'] = license_info.get('serial_number', 'unknown')
        except Exception as e:
            logger.warning(f"Error adding license headers: {e}")
        
        return response


class LicenseAPIMiddleware(MiddlewareMixin):
    """
    Middleware khusus untuk melindungi endpoint API tertentu dengan license check
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.license_manager = LicenseManager()
        
        # API endpoints yang memerlukan license check
        self.protected_api_paths = [
            '/ops/',
            '/tls/',
            # Tambahkan endpoint lain yang perlu dilindungi
        ]
    
    def process_request(self, request):
        """
        Process API requests yang memerlukan license
        """
        path = request.get_full_path()
        
        # Skip jika bukan protected API path
        if not self._is_protected_api_path(path):
            return None
        
        # Skip jika license check disabled
        if getattr(settings, 'SKIP_LICENSE_CHECK', False):
            return None
        
        try:
            is_licensed = self.license_manager.is_system_licensed()
            
            if not is_licensed:
                return redirect('/ops/license/activate/')
                
        except Exception as e:
            logger.error(f"Error in license API middleware for {path}: {e}")
            
            # Fail securely untuk API
            return JsonResponse({
                "error": "License verification failed",
                "detail": "Unable to verify system license",
                "error_code": "LICENSE_VERIFICATION_ERROR"
            }, status=503)
        
        return None
    
    def _is_protected_api_path(self, path):
        """
        Cek apakah path adalah protected API endpoint
        """
        for protected_path in self.protected_api_paths:
            if path.startswith(protected_path):
                return True
        return False

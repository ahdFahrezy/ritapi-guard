import requests
import logging
from django.conf import settings
from django.utils import timezone
from datetime import datetime
from .models import License, SystemStatus

logger = logging.getLogger(__name__)


class LicenseAPIService:
    """Service untuk integrasi dengan License API"""
    
    def __init__(self):
        # Prioritize local development, fallback to UAT
        self.base_urls = [
            "https://uat.ritapi.io/api"
        ]
        self.api_key = getattr(settings, 'LICENSE_API_KEY', 'ritapi-default-key-2025')
        self.timeout = 10
    
    def _get_working_base_url(self):
        """Find a working base URL by testing health endpoint"""
        for base_url in self.base_urls:
            try:
                response = requests.get(
                    f"{base_url}/health",
                    timeout=5
                )
                if response.status_code == 200:
                    logger.info(f"Using license API at: {base_url}")
                    return base_url
            except Exception as e:
                logger.warning(f"License API at {base_url} not available: {e}")
                continue
        
        logger.error("No working license API found")
        return None
    
    def activate_license(self, serial_number):
        """
        Aktivasi license menggunakan serial number
        
        Args:
            serial_number (str): Serial number license
            
        Returns:
            dict: Response dari API atau error info
        """
        base_url = self._get_working_base_url()
        logger.warning(f"Base URL: {base_url}")
        if not base_url:
            return {
                "success": False,
                "message": "License API service unavailable",
                "error_code": "API_UNAVAILABLE"
            }
        
        try:
            url = f"{base_url}/license/activate/{serial_number}"
            params = {"api_key": self.api_key}
            
            response = requests.post(url, params=params, timeout=self.timeout)
            print(response.json())
            if response.status_code == 200:
                data = response.json()
                logger.info(f"License activation successful for {serial_number}")
                return data
            else:
                # Handle error responses
                try:
                    error_data = response.json()
                    logger.warning(f"License activation failed for {serial_number}: {error_data}")
                    return error_data
                except:
                    return {
                        "success": False,
                        "message": f"HTTP {response.status_code} error",
                        "error_code": "HTTP_ERROR"
                    }
                    
        except requests.exceptions.Timeout:
            logger.error(f"License API timeout for {serial_number}")
            return {
                "success": False,
                "message": "License API timeout",
                "error_code": "TIMEOUT"
            }
        except requests.exceptions.ConnectionError:
            logger.error(f"License API connection error for {serial_number}")
            return {
                "success": False,
                "message": "License API connection error",
                "error_code": "CONNECTION_ERROR"
            }
        except Exception as e:
            logger.error(f"Unexpected error during license activation for {serial_number}: {e}")
            return {
                "success": False,
                "message": f"Unexpected error: {str(e)}",
                "error_code": "UNEXPECTED_ERROR"
            }
    
    def check_license_status(self, serial_number):
        """
        Cek status license
        
        Args:
            serial_number (str): Serial number license
            
        Returns:
            dict: Response dari API atau error info
        """
        base_url = self._get_working_base_url()
        if not base_url:
            return {
                "success": False,
                "message": "License API service unavailable",
                "error_code": "API_UNAVAILABLE"
            }
        
        try:
            url = f"{base_url}/license/status/{serial_number}"
            params = {"api_key": self.api_key}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"License status check successful for {serial_number}")
                return data
            else:
                try:
                    error_data = response.json()
                    logger.warning(f"License status check failed for {serial_number}: {error_data}")
                    return error_data
                except:
                    return {
                        "success": False,
                        "message": f"HTTP {response.status_code} error",
                        "error_code": "HTTP_ERROR"
                    }
                    
        except Exception as e:
            logger.error(f"Error checking license status for {serial_number}: {e}")
            return {
                "success": False,
                "message": f"Error checking status: {str(e)}",
                "error_code": "CHECK_ERROR"
            }


class LicenseManager:
    """Service untuk mengelola license sistem"""
    
    def __init__(self):
        self.api_service = LicenseAPIService()
    
    def activate_system_license(self, serial_number):
        """
        Aktivasi license sistem
        
        Args:
            serial_number (str): Serial number license
            
        Returns:
            dict: Result of activation process
        """
        try:
            # Normalize serial number
            serial_number = serial_number.strip().upper()
            
            # Get or create license record
            license_obj, created = License.objects.get_or_create(
                serial_number=serial_number,
                defaults={
                    'activation_status': False,
                    'activation_attempts': 0
                }
            )
            
            # Increment attempt counter
            license_obj.increment_attempts()
            
            # Call API to activate
            api_response = self.api_service.activate_license(serial_number)
            
            if api_response.get('success'):
                # Parse activated time
                activated_time_str = api_response.get('data', {}).get('activated_time')
                activated_time = None
                
                if activated_time_str:
                    try:
                        # Parse ISO format datetime
                        activated_time = datetime.fromisoformat(
                            activated_time_str.replace('Z', '+00:00')
                        )
                    except Exception as e:
                        logger.warning(f"Failed to parse activated_time: {e}")
                        activated_time = timezone.now()
                
                # Mark license as activated
                license_obj.mark_activated(activated_time)
                license_obj.error_message = None
                license_obj.save()
                
                # Update system status
                system_status = SystemStatus.get_instance()
                system_status.update_license_status(license_obj)
                
                logger.info(f"System license activated successfully: {serial_number}")
                return {
                    "success": True,
                    "message": "License activated successfully",
                    "license": license_obj,
                    "api_response": api_response
                }
            else:
                # Save error message
                error_message = api_response.get('message', 'Unknown error')
                license_obj.error_message = error_message
                license_obj.save()
                
                logger.warning(f"License activation failed: {serial_number} - {error_message}")
                return {
                    "success": False,
                    "message": error_message,
                    "error_code": api_response.get('error_code'),
                    "license": license_obj,
                    "api_response": api_response
                }
                
        except Exception as e:
            logger.error(f"Unexpected error during system license activation: {e}")
            return {
                "success": False,
                "message": f"System error: {str(e)}",
                "error_code": "SYSTEM_ERROR"
            }
    
    def check_system_license_status(self):
        """
        Cek status license sistem saat ini
        
        Returns:
            dict: Status license sistem
        """
        try:
            system_status = SystemStatus.get_instance()
            
            if not system_status.is_licensed or not system_status.current_license:
                return {
                    "is_licensed": False,
                    "message": "System is not licensed",
                    "license": None
                }
            
            # Validate current license with API
            license_obj = system_status.current_license
            api_response = self.api_service.check_license_status(license_obj.serial_number)
            
            if api_response.get('success'):
                # Update last check time
                license_obj.last_check_time = timezone.now()
                license_obj.save()
                
                system_status.last_license_check = timezone.now()
                system_status.save()
                
                return {
                    "is_licensed": True,
                    "message": "System is properly licensed",
                    "license": license_obj,
                    "api_response": api_response
                }
            else:
                # License validation failed, mark as inactive
                license_obj.mark_deactivated()
                system_status.update_license_status(None)
                
                return {
                    "is_licensed": False,
                    "message": "License validation failed",
                    "license": license_obj,
                    "api_response": api_response
                }
                
        except Exception as e:
            logger.error(f"Error checking system license status: {e}")
            return {
                "is_licensed": False,
                "message": f"Error checking license: {str(e)}",
                "error_code": "CHECK_ERROR"
            }
    
    def is_system_licensed(self):
        """
        Simple check untuk mengetahui apakah sistem sudah berlisensi
        
        Returns:
            bool: True jika sistem berlisensi
        """
        try:
            system_status = SystemStatus.get_instance()
            return system_status.is_licensed and system_status.current_license and system_status.current_license.is_active
        except:
            return False
    
    def get_current_license_info(self):
        """
        Dapatkan informasi license saat ini
        
        Returns:
            dict: Informasi license atau None
        """
        try:
            system_status = SystemStatus.get_instance()
            if system_status.current_license:
                license_obj = system_status.current_license
                return {
                    "serial_number": license_obj.serial_number,
                    "activation_status": license_obj.activation_status,
                    "activated_time": license_obj.activated_time,
                    "last_check_time": license_obj.last_check_time,
                    "activation_attempts": license_obj.activation_attempts
                }
            return None
        except:
            return None

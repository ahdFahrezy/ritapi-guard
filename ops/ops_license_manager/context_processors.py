from .services import LicenseManager

def license_status(request):
    manager = LicenseManager()
    return {
        "is_licensed": manager.is_system_licensed(),
        "license_info": manager.get_current_license_info()
    }
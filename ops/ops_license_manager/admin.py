from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import License, SystemStatus


@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = [
        'serial_number', 
        'activation_status_badge', 
        'activated_time', 
        'activation_attempts',
        'last_check_time',
        'created_at'
    ]
    list_filter = ['activation_status', 'created_at', 'activated_time']
    search_fields = ['serial_number']
    readonly_fields = [
        'serial_number', 
        'activated_time', 
        'activation_attempts', 
        'last_check_time',
        'created_at', 
        'updated_at'
    ]
    
    fieldsets = (
        ('License Information', {
            'fields': ('serial_number', 'activation_status')
        }),
        ('Activation Details', {
            'fields': ('activated_time', 'activation_attempts', 'last_check_time')
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def activation_status_badge(self, obj):
        if obj.activation_status:
            return format_html(
                '<span style="color: green; font-weight: bold;">✅ Active</span>'
            )
        else:
            return format_html(
                '<span style="color: red; font-weight: bold;">❌ Inactive</span>'
            )
    activation_status_badge.short_description = 'Status'
    
    def has_add_permission(self, request):
        # Prevent manual creation of license records through admin
        return False
    
    def has_delete_permission(self, request, obj=None):
        # Allow deletion only for superusers
        return request.user.is_superuser
    
    actions = ['deactivate_licenses', 'test_license_api']
    
    def deactivate_licenses(self, request, queryset):
        """Deactivate selected licenses"""
        count = 0
        for license_obj in queryset:
            if license_obj.activation_status:
                license_obj.mark_deactivated()
                count += 1
        
        self.message_user(
            request, 
            f'{count} license(s) have been deactivated.'
        )
    deactivate_licenses.short_description = "Deactivate selected licenses"
    
    def test_license_api(self, request, queryset):
        """Test license API connection for selected licenses"""
        from .services import LicenseAPIService
        
        api_service = LicenseAPIService()
        working_url = api_service._get_working_base_url()
        
        if working_url:
            self.message_user(
                request,
                f'License API is working at: {working_url}',
                level='SUCCESS'
            )
        else:
            self.message_user(
                request,
                'License API is not available',
                level='ERROR'
            )
    test_license_api.short_description = "Test license API connection"


@admin.register(SystemStatus)
class SystemStatusAdmin(admin.ModelAdmin):
    list_display = [
        'is_licensed_badge', 
        'current_license_display', 
        'last_license_check',
        'updated_at'
    ]
    readonly_fields = [
        'current_license', 
        'last_license_check', 
        'created_at', 
        'updated_at'
    ]
    
    fieldsets = (
        ('System Status', {
            'fields': ('is_licensed', 'current_license')
        }),
        ('Timestamps', {
            'fields': ('last_license_check', 'created_at', 'updated_at')
        }),
    )
    
    def is_licensed_badge(self, obj):
        if obj.is_licensed:
            return format_html(
                '<span style="color: green; font-weight: bold;">✅ Licensed</span>'
            )
        else:
            return format_html(
                '<span style="color: red; font-weight: bold;">❌ Not Licensed</span>'
            )
    is_licensed_badge.short_description = 'License Status'
    
    def current_license_display(self, obj):
        if obj.current_license:
            return format_html(
                '<a href="{}">{}</a>',
                reverse('admin:ops_license_manager_license_change', args=[obj.current_license.pk]),
                obj.current_license.serial_number
            )
        return '-'
    current_license_display.short_description = 'Current License'
    
    def has_add_permission(self, request):
        # Only allow one SystemStatus instance
        return not SystemStatus.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of SystemStatus
        return False
    
    actions = ['refresh_license_status', 'force_license_check']
    
    def refresh_license_status(self, request, queryset):
        """Refresh license status for selected system status records"""
        from .services import LicenseManager
        
        license_manager = LicenseManager()
        
        for system_status in queryset:
            try:
                status_result = license_manager.check_system_license_status()
                
                if status_result.get('is_licensed'):
                    self.message_user(
                        request,
                        f'License status refreshed: System is licensed',
                        level='SUCCESS'
                    )
                else:
                    self.message_user(
                        request,
                        f'License status refreshed: System is not licensed - {status_result.get("message")}',
                        level='WARNING'
                    )
            except Exception as e:
                self.message_user(
                    request,
                    f'Error refreshing license status: {str(e)}',
                    level='ERROR'
                )
    refresh_license_status.short_description = "Refresh license status"
    
    def force_license_check(self, request, queryset):
        """Force license check via API"""
        from .services import LicenseManager
        
        license_manager = LicenseManager()
        
        try:
            # Get current license info
            current_license_info = license_manager.get_current_license_info()
            
            if current_license_info:
                # Check with API
                api_service = license_manager.api_service
                api_response = api_service.check_license_status(
                    current_license_info['serial_number']
                )
                
                if api_response.get('success'):
                    self.message_user(
                        request,
                        f'API check successful: {api_response.get("message")}',
                        level='SUCCESS'
                    )
                else:
                    self.message_user(
                        request,
                        f'API check failed: {api_response.get("message")}',
                        level='ERROR'
                    )
            else:
                self.message_user(
                    request,
                    'No current license found to check',
                    level='WARNING'
                )
        except Exception as e:
            self.message_user(
                request,
                f'Error during API check: {str(e)}',
                level='ERROR'
            )
    force_license_check.short_description = "Force license API check"


# Customize admin site header and title
admin.site.site_header = "RITAPI License Management"
admin.site.site_title = "RITAPI Admin"
admin.site.index_title = "Welcome to RITAPI Administration"

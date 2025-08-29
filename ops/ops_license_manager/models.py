from django.db import models
from django.utils import timezone


class License(models.Model):
    """Model untuk menyimpan informasi license sistem"""
    
    serial_number = models.CharField(max_length=20, unique=True, db_index=True)
    activation_status = models.BooleanField(default=False)
    activated_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional tracking fields
    activation_attempts = models.IntegerField(default=0)
    last_check_time = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'ops_license_manager_license'
        verbose_name = 'License'
        verbose_name_plural = 'Licenses'
    
    def __str__(self):
        return f"{self.serial_number} ({'Active' if self.activation_status else 'Inactive'})"
    
    @property
    def is_active(self):
        """Check if license is currently active"""
        return self.activation_status
    
    def mark_activated(self, activated_time=None):
        """Mark license as activated"""
        self.activation_status = True
        self.activated_time = activated_time or timezone.now()
        self.save()
    
    def mark_deactivated(self):
        """Mark license as deactivated"""
        self.activation_status = False
        self.save()
    
    def increment_attempts(self):
        """Increment activation attempts counter"""
        self.activation_attempts += 1
        self.save()


class SystemStatus(models.Model):
    """Model untuk menyimpan status sistem secara keseluruhan"""
    
    is_licensed = models.BooleanField(default=False)
    current_license = models.ForeignKey(
        License, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='system_status'
    )
    last_license_check = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'ops_license_manager_system_status'
        verbose_name = 'System Status'
        verbose_name_plural = 'System Status'
    
    def __str__(self):
        return f"System Licensed: {self.is_licensed}"
    
    @classmethod
    def get_instance(cls):
        """Get or create singleton instance"""
        instance, created = cls.objects.get_or_create(pk=1)
        return instance
    
    def update_license_status(self, license_obj=None):
        """Update system license status"""
        if license_obj and license_obj.is_active:
            self.is_licensed = True
            self.current_license = license_obj
        else:
            self.is_licensed = False
            self.current_license = None
        
        self.last_license_check = timezone.now()
        self.save()

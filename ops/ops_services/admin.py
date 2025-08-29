from django.contrib import admin
from .models import Service

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('uuid', 'target_base_url', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('target_base_url',)
    readonly_fields = ('uuid', 'timestamp')
    ordering = ('-timestamp',)
    
    fieldsets = (
        ('Service Information', {
            'fields': ('uuid', 'target_base_url')
        }),
        ('Metadata', {
            'fields': ('timestamp',),
            'classes': ('collapse',)
        }),
    )

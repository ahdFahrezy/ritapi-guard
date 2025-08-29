from django.contrib import admin
from .models import JsonSchema

@admin.register(JsonSchema)
class JsonSchemaAdmin(admin.ModelAdmin):
    list_display = ("name", "endpoint", "get_service", "is_active", "timestamp")
    search_fields = ("name", "endpoint", "service__target_base_url")
    list_filter = ("is_active", "service")

    def get_service(self, obj):
        return obj.service.target_base_url if obj.service else "-"
    get_service.short_description = "Service Target"

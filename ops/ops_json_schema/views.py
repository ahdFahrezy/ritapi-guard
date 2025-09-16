# ops/views.py
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from json_enforcer.models import JsonSchema
from django.views.decorators.http import require_POST
from ops.ops_services.models import Service
from uuid import UUID
import json
from django.http import JsonResponse


@login_required
def jsonschema_dashboard(request):
    """
    Dashboard CRUD JsonSchema dengan modal
    """
    schemas = JsonSchema.objects.all().order_by("-timestamp")
    paginator = Paginator(schemas, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    
    services = Service.objects.all().order_by("-timestamp")

    return render(request, "ops_template/json_dashboard.html", {
        "page_obj": page_obj,
        "services": services,
    })


@login_required
def jsonschema_create(request):
    if request.method == "POST":
        name = request.POST.get("name")
        endpoint = request.POST.get("endpoint")
        schema_json = request.POST.get("schema_json")
        description = request.POST.get("description")
        service_uuid = request.POST.get("service_uuid")
        
        try:
            schema_data = json.loads(schema_json) if schema_json else {}
        except json.JSONDecodeError as e:
            return JsonResponse({
                "success": False,
                "message": f"Schema JSON Invalid"
            }, status=400)

        try:
            JsonSchema.objects.create(
                name=name,
                endpoint=endpoint,
                schema_json=schema_data,
                description=description,
                service=Service.objects.filter(uuid=UUID(service_uuid)).first() if service_uuid else None,
            )
        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": f"Gagal menyimpan schema: {str(e)}"
            }, status=500)
        return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=400)


@login_required
def jsonschema_update(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    if request.method == "POST":
        schema.name = request.POST.get("name")
        schema.endpoint = request.POST.get("endpoint")
        schema.schema_json = request.POST.get("schema_json")
        schema.description = request.POST.get("description")
        schema.service = Service.objects.filter(uuid=UUID(request.POST.get("service_uuid"))).first()
        schema.save()
        return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=400)


@login_required
def jsonschema_delete(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    schema.delete()
    return JsonResponse({"success": True})

@login_required
@require_POST
def jsonschema_toggle(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    schema.is_active = not schema.is_active
    schema.save()
    return JsonResponse({"success": True, "is_active": schema.is_active})

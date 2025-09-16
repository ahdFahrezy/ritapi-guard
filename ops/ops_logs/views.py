from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from decision_engine.models import RequestLog  
from django.core.paginator import Paginator
from django.http import HttpResponse
from openpyxl import Workbook
from django.core.serializers import serialize
from django.http import JsonResponse

@login_required
def requestlog_list(request):
    query = request.GET.get("q", "")
    decision_filter = request.GET.get("decision", "")
    page_number = request.GET.get("page", 1)

    logs = RequestLog.objects.all().order_by("-timestamp")

    if query:
        logs = logs.filter(ip_address__icontains=query)

    if decision_filter:
        logs = logs.filter(decision=decision_filter)

    paginator = Paginator(logs, 10)  # 10 rows per page
    page_obj = paginator.get_page(page_number)

    context = {
        "logs": page_obj,
        "query": query,
        "decision_filter": decision_filter,
    }
    return render(request, "ops_template/requestlog_list.html", context)

@login_required
def export_requestlog_excel(request):
    logs = RequestLog.objects.all().order_by("-timestamp")

    wb = Workbook()
    ws = wb.active
    ws.title = "Request Logs"

    # Header (added No.)
    ws.append([
        "No.", "IP Address", "Path", "Method", "Body Size", "Score",
        "Decision", "Reason", "Timestamp"
    ])

    # Data with numbering
    for idx, log in enumerate(logs, start=1):
        ws.append([
            idx,  # Row number
            log.ip_address,
            log.path,
            log.method,
            log.body_size,
            log.score,
            log.decision,
            log.reason,
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        ])

    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="request_logs.xlsx"'
    wb.save(response)
    return response

@login_required
def requestlog_data(request):
    logs = RequestLog.objects.all().order_by("-timestamp")[:200]  # limit agar ringan
    data = []

    for log in logs:
        data.append({
            "ip_address": log.ip_address,
            "path": log.path,
            "method": log.method,
            # "body_size": log.body_size,
            "score": log.score,
            "decision": log.decision,
            "reason": log.reason or "-",
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        })

    return JsonResponse({"data": data})
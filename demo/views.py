from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.utils import timezone
import uuid,math


def demo_page(request):
    alerts = request.session.get("alerts", [])
    blocks = request.session.get("blocks", [])
    message = None

    add_type = request.GET.get("add")
    if add_type:
        if add_type == "TLS_ANALYZER_ERROR":
            data = {
                "type": "TLS_ANALYZER_ERROR",
                "ip": "127.0.0.1",
                "severity": "Low",
                "detail": "TLS analysis failed for host=127.0.0.1:8001",
                "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            alerts.insert(0, data)

        elif add_type == "SUSPICIOUS_ASN":
            data = {
                "type": "SUSPICIOUS_ASN",
                "ip": "103.144.55.12",
                "severity": "Medium",
                "detail": "ASN 45678 marked as suspicious",
                "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            alerts.insert(0, data)

        elif add_type == "BLOCKED":
            ip = "203.0.113.77"
            if any(b["ip"] == ip for b in blocks):
                message = "You already block this IP"
            else:
                data = {
                    "type": "BLOCKED",
                    "ip": ip,
                    "severity": "High",
                    "detail": "Malformed JSON detected - request blocked",
                    "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                alerts.insert(0, data)
                blocks.insert(0, data)

        elif add_type == "SUCCESS_LOGIN":
            message = {
                "status": "success",
                "user": "demo",
                "token": "abc123xyz"
            }

        request.session["alerts"] = alerts
        request.session["blocks"] = blocks
        request.session["message"] = message
        return redirect("demo-page")

    # Ambil message sekali pakai
    message = request.session.pop("message", None)
    target_id = str(uuid.uuid4())

    # --- Pagination untuk Alerts ---
    page_alerts = int(request.GET.get("page_alerts", 1))
    per_page = 5
    total_alerts = len(alerts)
    total_pages_alerts = max(1, math.ceil(total_alerts / per_page))
    start = (page_alerts - 1) * per_page
    end = start + per_page
    alerts_paginated = alerts[start:end]
    page_range_alerts = list(range(1, total_pages_alerts + 1))

    # --- Pagination untuk Blocks ---
    page_blocks = int(request.GET.get("page_blocks", 1))
    total_blocks = len(blocks)
    total_pages_blocks = max(1, math.ceil(total_blocks / per_page))
    start_b = (page_blocks - 1) * per_page
    end_b = start_b + per_page
    blocks_paginated = blocks[start_b:end_b]
    page_range_blocks = list(range(1, total_pages_blocks + 1))

    return render(request, "ops_template/demo.html", {
        "alerts": alerts_paginated,
        "blocks": blocks_paginated,
        "message": message,
        "target_id": target_id,
        # Alerts
        "page_alerts": page_alerts,
        "page_range_alerts": page_range_alerts,
        # Blocks
        "page_blocks": page_blocks,
        "page_range_blocks": page_range_blocks,
    })

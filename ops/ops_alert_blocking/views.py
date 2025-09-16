from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.contrib import messages

from alert_blocking.models import Alert, BlockedIP
from alert_blocking.services import BlockingService
from django.db.models import Q


# ===================== ALERT MANAGEMENT =====================

@login_required
def alert_dashboard(request):
    """Alert Management with search & filtering"""
    query = request.GET.get("q", "").strip()
    severity_filter = request.GET.get("severity", "")
    status_filter = request.GET.get("status", "")

    alerts = Alert.objects.all().order_by("-timestamp")

    # Flag buat cek apakah ada filter dipakai
    filters_applied = any([query, severity_filter, status_filter])

    # 🔍 Search by message or source IP (sesuaikan field di model Alert)
    if query:
        alerts = alerts.filter(
            Q(ip_address__icontains=query) |
            Q(alert_type__icontains=query) |
            Q(detail__icontains=query)
        )

    # 🎯 Filter by severity
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)

    # Pagination
    paginator = Paginator(alerts, 10)
    page_number = request.GET.get("page")
    alerts_page = paginator.get_page(page_number)

    # Error message hanya muncul kalau ada filter dipakai
    error_message = None
    if filters_applied and not alerts.exists():
        error_message = "No alerts found with the given filters."

    return render(request, "ops_template/alerts.html", {
        "alerts": alerts_page,
        "query": query,
        "severity_filter": severity_filter,
        "status_filter": status_filter,
        "error_message": error_message
    })

@login_required
def resolve_alert(request, alert_id):
    """Tandai alert sebagai resolved"""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.resolved = True
    alert.save()
    messages.success(request, f"Alert {alert.id} berhasil diresolve ✅")
    return redirect("ops.ops_alert")


@login_required
def block_ip_from_alert(request, ip_address):
    """Block IP langsung dari alert"""
    BlockingService.block_ip(ip_address, reason="Blocked from alert", severity="high")
    messages.warning(request, f"IP {ip_address} berhasil diblok 🚫")
    return redirect("ops_blocked_ip_dashboard")


# ===================== BLOCKED IP MANAGEMENT =====================

@login_required
def blocked_ip_dashboard(request):
    """Blocked IP Management with search & filtering"""
    query = request.GET.get("q", "").strip()
    severity_filter = request.GET.get("severity", "")
    status_filter = request.GET.get("status", "")

    blocked_ips = BlockedIP.objects.all().order_by("-blocked_at")

    # Flag buat cek apakah ada filter dipakai
    filters_applied = any([query, severity_filter, status_filter])

    # 🔍 Search by IP
    if query:
        blocked_ips = blocked_ips.filter(ip_address__icontains=query)

    # 🎯 Filter by severity
    if severity_filter:
        blocked_ips = blocked_ips.filter(severity=severity_filter)

    # 🎯 Filter by status
    if status_filter == "active":
        blocked_ips = blocked_ips.filter(active=True)
    elif status_filter == "inactive":
        blocked_ips = blocked_ips.filter(active=False)

    # Pagination
    paginator = Paginator(blocked_ips, 10)
    page_number = request.GET.get("page")
    blocked_page = paginator.get_page(page_number)

    # Error message hanya muncul kalau ada filter dipakai
    error_message = None
    if filters_applied and not blocked_ips.exists():
        error_message = "No blocked IPs found with the given filters."

    return render(request, "ops_template/blocked_ips.html", {
        "blocked_ips": blocked_page,
        "query": query,
        "severity_filter": severity_filter,
        "status_filter": status_filter,
        "error_message": error_message
    })

@login_required
def unblock_ip(request, ip_address):
    """Unblock IP"""
    blocked = BlockingService.unblock_ip(ip_address)
    if blocked:
        messages.success(request, f"IP {ip_address} berhasil di-unblock ✅")
    else:
        messages.error(request, f"IP {ip_address} tidak ditemukan ❌")
    return redirect("ops_blocked_ip_dashboard")

@login_required
def block_ip_manual(request, ip_address):
    """Block ulang IP secara manual (default high severity permanent)."""
    blocked = BlockingService.block_ip(
        ip_address,
        reason="Manual block from dashboard",
        severity="high",
        duration_minutes=None  # permanent
    )
    if blocked:
        messages.warning(request, f"IP {ip_address} berhasil diblok ulang 🚫")
    else:
        messages.error(request, f"Gagal memblokir IP {ip_address}")
    return redirect("ops_blocked_ip_dashboard")
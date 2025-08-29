from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from alert_blocking.models import Alert, BlockedIP
from tls_analyzer.models import TlsAnalyzer
from json_enforcer.models import JsonSchema

# kalau ada JSON schema
# from ops.ops_json_enforcer.models import JsonSchema


@login_required
def dashboard(request):
    # Hitung statistik utama
    total_alerts = Alert.objects.count()
    total_blocked = BlockedIP.objects.count()
    total_tls = TlsAnalyzer.objects.count()
    total_schemas = JsonSchema.objects.filter(is_active=True).count()

    # Chart 1: hitung alert per severity
    alerts_high = Alert.objects.filter(severity="High").count()
    alerts_medium = Alert.objects.filter(severity="Medium").count()
    alerts_low = Alert.objects.filter(severity="Low").count()

    # Chart 2: blocked IP 7 hari terakhir
    today = timezone.now().date()
    last7days = [today - timedelta(days=i) for i in range(6, -1, -1)]

    blocked_days = []
    for day in last7days:
        count = BlockedIP.objects.filter(blocked_at__date=day).count()
        blocked_days.append({"date": day.strftime("%d %b"), "count": count})

    context = {
        # Statistik angka
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
        "total_tls": total_tls,
        "total_schemas": total_schemas,

        # Data chart
        "alerts_high": alerts_high,
        "alerts_medium": alerts_medium,
        "alerts_low": alerts_low,
        "blocked_days": blocked_days,

        # Data terbaru
        "recent_alerts": Alert.objects.order_by("-timestamp")[:5],
        "recent_blocked": BlockedIP.objects.order_by("-blocked_at")[:5],
        "recent_tls": TlsAnalyzer.objects.order_by("-timestamp")[:5],
    }
    return render(request, "ops/dashboard.html", context)

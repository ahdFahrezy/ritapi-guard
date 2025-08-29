from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import AlertService, BlockingService
from .models import Alert, BlockedIP


class CreateAlertView(APIView):
    def post(self, request):
        data = request.data
        alert = AlertService.create_alert(
            alert_type=data.get("alert_type"),
            ip_address=data.get("ip_address"),
            detail=data.get("detail"),
            severity=data.get("severity", "low"),
        )
        return Response({"message": "Alert created", "id": alert.id}, status=status.HTTP_201_CREATED)


class BlockIPView(APIView):
    def post(self, request):
        data = request.data
        blocked = BlockingService.block_ip(
            ip_address=data.get("ip_address"),
            reason=data.get("reason"),
            severity=data.get("severity", "low"),
            duration_minutes=data.get("duration_minutes"),
        )
        return Response({"message": "IP blocked", "id": blocked.id}, status=status.HTTP_201_CREATED)


class UnblockIPView(APIView):
    def post(self, request):
        ip_address = request.data.get("ip_address")
        blocked = BlockingService.unblock_ip(ip_address)
        if blocked:
            return Response({"message": f"IP {ip_address} unblocked"})
        return Response({"error": "IP tidak ditemukan"}, status=status.HTTP_404_NOT_FOUND)


class CheckIPView(APIView):
    def get(self, request, ip_address):
        blocked = BlockingService.is_blocked(ip_address)
        return Response({"ip_address": ip_address, "blocked": blocked})


class ListAlertsView(APIView):
    def get(self, request):
        alerts = Alert.objects.all().order_by("-timestamp")[:10]
        return Response([{
            "id": a.id,
            "alert_type": a.alert_type,
            "ip_address": a.ip_address,
            "severity": a.severity,
            "detail": a.detail,
            "resolved": a.resolved,
            "timestamp": a.timestamp,
        } for a in alerts])


class ListBlockedIPsView(APIView):
    def get(self, request):
        blocked_ips = BlockedIP.objects.filter(active=True).order_by("-blocked_at")
        return Response([{
            "id": b.id,
            "ip_address": b.ip_address,
            "severity": b.severity,
            "reason": b.reason,
            "active": b.active,
            "blocked_at": b.blocked_at,
            "expires_at": b.expires_at,
        } for b in blocked_ips])

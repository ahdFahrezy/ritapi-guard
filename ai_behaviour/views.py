from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import AiProfilerService
from .models import BehaviourLogs, BehaviourAnomaly


class BehaviourLogView(APIView):
    """
    API untuk menerima log request dan simpan ke DB
    """
    def post(self, request):
        data = request.data
        log = AiProfilerService.log_request(
            endpoint=data.get("endpoint", "/"),
            ip=data.get("ip_address"),
            method=data.get("method", "GET"),
            payload_size=int(data.get("payload_size", 0)),
            user_agent=data.get("user_agent", "UNKNOWN"),
            status_code=int(data.get("status_code", 200)),
            response_time_ms=float(data.get("response_time_ms", 0)),
        )
        return Response(
            {"id": log.id, "ip": log.ip_address, "endpoint": log.endpoint},
            status=status.HTTP_201_CREATED
        )


class AnomalyListView(APIView):
    """
    Ambil daftar anomaly terbaru
    """
    def get(self, request):
        anomalies = BehaviourAnomaly.objects.all().order_by("-detected_at")[:20]
        return Response([
            {
                "id": a.id,
                "ip": a.ip_address,
                "type": a.anomaly_type,
                "risk": a.risk_score,
                "time": a.detected_at,
                "resolved": a.resolved,
                "detected_by": a.detected_by,   # ⬅️ tambahan
            }
            for a in anomalies
        ])


class BehaviourLogHistoryView(APIView):
    """
    Ambil 20 log Behaviour terakhir
    """
    def get(self, request):
        logs = BehaviourLogs.objects.all().order_by("-timestamp")[:20]
        return Response([
            {
                "id": l.id,
                "endpoint": l.endpoint,
                "ip": l.ip_address,
                "method": l.method,
                "payload_size": l.payload_size,
                "user_agent": l.user_agent,
                "status_code": l.status_code,
                "response_time_ms": l.response_time_ms,
                "timestamp": l.timestamp,
            }
            for l in logs
        ])

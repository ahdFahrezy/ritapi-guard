from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import IpReputationService
from .models import IpReputation


class IpReputationLookupView(APIView):
    def post(self, request):
        ip = request.data.get("ip")
        if not ip:
            return Response({"error": "Parameter 'ip' wajib diisi"}, status=status.HTTP_400_BAD_REQUEST)

        record = IpReputationService.check_reputation(ip)

        # Ambil sources dari field scores (kalau ada)
        sources = record.scores.get("sources", [])
        malicious = record.reputation_score < 0  # kalau skornya negatif → malicious

        return Response({
            "id": record.id,
            "ip_address": record.ip_address,
            "reputation_score": record.reputation_score,
            "isp": record.isp,
            "country": record.country,
            "is_tor": record.is_tor,
            "sources": sources,
            "malicious": malicious,
            "timestamp": record.timestamp,
        })

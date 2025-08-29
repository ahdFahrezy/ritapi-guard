from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import TlsAnalyzerService
from .models import TlsAnalyzer




class TlsCheckView(APIView):
    """
    Endpoint untuk menganalisis TLS certificate dari domain tertentu.
    """

    def post(self, request):
        domain = request.data.get("domain")

        if not domain:
            return Response({"error": "Parameter 'domain' wajib diisi"}, status=status.HTTP_400_BAD_REQUEST)

        record = TlsAnalyzerService.analyze_tls(domain)

        return Response({
            "id": record.id,
            "hostname": record.hostname,
            "ip_address": record.ip_address,
            "subject": record.subject,
            "issuer": record.issuer,
            "expires": record.expires,
            "is_valid": record.is_valid,
            "serial_number": record.serial_number,
            "timestamp": record.timestamp,
        })


class TlsHistoryView(APIView):
    """
    Endpoint untuk melihat history hasil TLS Analyzer.
    Bisa pakai query param:
      - ?limit=20 (default 10)
      - ?domain=example.com (filter per domain)
    """

    def get(self, request):
        limit = int(request.query_params.get("limit", 10))
        domain = request.query_params.get("domain", None)

        qs = TlsAnalyzer.objects.all()
        if domain:
            qs = qs.filter(hostname__icontains=domain)

        records = qs.order_by("-timestamp")[:limit]

        data = [
            {
                "id": r.id,
                "hostname": r.hostname,
                "ip_address": r.ip_address,
                "issuer": r.issuer,
                "is_valid": r.is_valid,
                "expires": r.expires,
                "timestamp": r.timestamp,
            }
            for r in records
        ]
        return Response(data)

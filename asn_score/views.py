from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import AsnScoreService
from .models import AsnInfo


class AsnLookupView(APIView):
    """
    Terima IP dari request, lookup ASN, simpan ke DB, dan return hasil.
    """
    def post(self, request):
        ip = request.data.get("ip")
        if not ip:
            return Response(
                {"error": "Parameter 'ip' wajib diisi"},
                status=status.HTTP_400_BAD_REQUEST
            )

        record = AsnScoreService.lookup_asn(ip)
        return Response({
            "id": record.id,
            "ip_address": record.ip_address,
            "asn_number": record.asn_number,
            "asn_description": record.asn_description,   # ✅ tambahkan ini
            "trust_score": record.trust_score,
            "timestamp": record.timestamp,
        })


class AsnHistoryView(APIView):
    """
    Ambil 10 hasil ASN terakhir dari DB
    """
    def get(self, request):
        records = AsnInfo.objects.all().order_by("-timestamp")[:10]
        return Response([
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "asn_number": r.asn_number,
                "asn_description": r.asn_description,   # ✅ ubah ke field yang benar
                "trust_score": r.trust_score,
                "timestamp": r.timestamp,
            }
            for r in records
        ])
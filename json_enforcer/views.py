from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import JsonEnforcerService
import json

class JsonValidateView(APIView):
    """
    Terima payload dan endpoint, lalu validasi berdasarkan schema JSON.
    """
    def post(self, request):
        try:
            endpoint = request.data.get("endpoint")
            payload = request.data.get("payload")
        except Exception as e:
            return Response(
                {
                    "error": "Payload JSON tidak valid",
                    "hint": "Periksa tanda kutip, koma, atau struktur JSON kamu",
                    "detail": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if not endpoint or payload is None:
            return Response(
                {
                    "error": "Parameter 'endpoint' dan 'payload' wajib diisi",
                    "hint": "Contoh: {\"endpoint\": \"/api/user/create/\", \"payload\": {\"username\": \"foo\"}}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        result = JsonEnforcerService.validate_payload(endpoint, payload)

        if result["valid"]:
            return Response(
                {
                    "message": "Payload valid ✅",
                    "endpoint": endpoint,
                    "validated_data": payload,
                    "schema_check": result
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    "error": "Payload tidak sesuai schema ❌",
                    "endpoint": endpoint,
                    "details": result.get("errors", []),
                    "hint": "Pastikan field sesuai dengan schema JSON yang sudah ditentukan"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

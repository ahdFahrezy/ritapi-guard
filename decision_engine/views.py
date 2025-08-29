import requests
from django.http import JsonResponse, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .models import RequestLog

from tls_analyzer.services import analyze_tls_cert
from asn_score.services import lookup_asn
from ip_reputation.services import reputation_score
from json_enforcer.services import validate_json
from ai_behaviour.services import log_request, is_anomalous
from alert_blocking.services import BlockingService, AlertService

TARGET_BACKEND = "http://127.0.0.1:7000"

class DecisionProxyMiddleware(MiddlewareMixin):
    def process_request(self, request):
        path = request.get_full_path()

        if path.startswith("/admin") or path.startswith("/static") or path.startswith("/__debug__"):
            return None

        client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
        body = request.body or b""

        # cek ke modul
        tls = analyze_tls_cert(request.headers.get("Host", "localhost"))
        asn = lookup_asn(client_ip)
        rep = reputation_score(client_ip)
        json_check = validate_json(path, body)
        log_request(client_ip, path, len(body))
        anomalous = is_anomalous(client_ip)

        score = asn.get("trust_score", 0) + rep.get("score", 0)
        if not json_check.get("valid", True):
            score -= 5
        if tls.get("tls_valid") is False:
            score -= 1
        if anomalous:
            score -= 4

        # default log entry
        decision = "allow"
        reason = "ok"

        # cek blocking
        if BlockingService.is_blocked(client_ip):
            decision = "block"
            reason = "already_blocked"
            RequestLog.objects.create(
                ip_address=client_ip, path=path, method=request.method,
                body_size=len(body), score=score, decision=decision, reason=reason
            )
            return JsonResponse({"error": "Blocked by blocklist"}, status=403)

        if score < -4:
            decision = "block"
            reason = "score_too_low"
            BlockingService.block_ip(client_ip, reason="Score too low", severity="high")
            AlertService.create_alert("BLOCKED", client_ip, "Auto block by decision engine", "high")
            RequestLog.objects.create(
                ip_address=client_ip, path=path, method=request.method,
                body_size=len(body), score=score, decision=decision, reason=reason
            )

            return JsonResponse({"error": "Blocked by RITAPI", "score": score}, status=403)

        # forward ke backend
        try:
            headers = dict(request.headers)
            headers.pop("Host", None)

            resp = requests.request(
                method=request.method,
                url=f"{TARGET_BACKEND}{path}",
                headers=headers,
                data=body,
                timeout=6,
            )
            response = HttpResponse(resp.content, status=resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("content-encoding", "transfer-encoding", "connection"):
                    response[k] = v

            # log sukses allow
            RequestLog.objects.create(
                ip_address=client_ip, path=path, method=request.method,
                body_size=len(body), score=score, decision=decision, reason=reason
            )
            return response

        except Exception as e:
            decision = "block"
            reason = f"backend_error: {e}"
            AlertService.create_alert("BACKEND_ERROR", client_ip, str(e), "critical")
            RequestLog.objects.create(
                ip_address=client_ip, path=path, method=request.method,
                body_size=len(body), score=score, decision=decision, reason=reason
            )
            return JsonResponse({"error": "backend_unreachable", "detail": str(e)}, status=502)

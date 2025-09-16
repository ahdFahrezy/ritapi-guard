import logging
import json
import hashlib
import pickle
import requests
import os
from django.http import JsonResponse, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .models import RequestLog


# Import Service model for dynamic backend routing
try:
    from ops.ops_services.models import Service
except ImportError:
    Service = None

CACHE_TTL = getattr(settings, "BACKEND_RESPONSE_CACHE_TTL", int(os.getenv("BACKEND_RESPONSE_CACHE_TTL", "30")))
ASN_TLS_CACHE_TTL = getattr(settings, "ASN_TLS_CACHE_TTL", int(os.getenv("ASN_TLS_CACHE_TTL", "30")))
# === Redis Singleton ===
class RedisClientSingleton:
    _instance = None

    @classmethod
    def get_client(cls):
        if cls._instance is None:
            try:
                import redis
                cls._instance = redis.from_url(
                    getattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0"),
                    decode_responses=False
                )
                # test koneksi
                cls._instance.ping()
                logger.info("Redis client initialized (singleton)")
            except Exception as e:
                logger.warning("Redis unavailable, cache disabled: %s", e)
                cls._instance = None
        return cls._instance
    
# === Service lookup cache ===
def _get_service_from_db(target_id: str):
    """In-memory fallback lookup kalau Redis tidak ada."""
    try:
        service = Service.objects.get(uuid=target_id)
        return {
            "id": service.id,
            "uuid": str(service.uuid),
            "target_base_url": service.target_base_url,
        }
    except Service.DoesNotExist:
        return None


def get_service_cached(target_id: str):
    cache_key = f"ritapi:service:{target_id}"
    redis_client = RedisClientSingleton.get_client()

    # coba ambil dari Redis
    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    # fallback ke DB langsung
    service_data = _get_service_from_db(target_id)

    if service_data and redis_client:
        try:
            redis_client.setex(cache_key, CACHE_TTL, json.dumps(service_data))
        except Exception:
            pass
    return service_data

# === Allowed service IDs cache ===
def _get_allowed_service_ids_from_db(max_services: int):
    """In-memory fallback untuk daftar service IDs."""
    return list(Service.objects.values_list("id", flat=True).order_by("id")[:max_services])

def get_allowed_service_ids(max_services: int):
    cache_key = f"ritapi:allowed_services:{max_services}"
    redis_client = RedisClientSingleton.get_client()

    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    # fallback ke DB langsung
    ids = _get_allowed_service_ids_from_db(max_services)

    if redis_client:
        try:
            redis_client.setex(cache_key, CACHE_TTL, json.dumps(ids))
        except Exception:
            pass
    return ids    
    
logger = logging.getLogger(__name__)

# === Safely import your 6 modules (best-effort) ===
def _safe_imports():
    mods = {}
    try:
        from tls_analyzer.services import analyze_tls_cert
        mods["analyze_tls_cert"] = analyze_tls_cert
    except Exception:
        mods["analyze_tls_cert"] = None

    try:
        from asn_score.services import AsnScoreService
        mods["lookup_asn"] = AsnScoreService.lookup_asn
    except Exception:
        mods["lookup_asn"] = None

    try:
        from ip_reputation.services import IpReputationService
        mods["ip_rep"] = IpReputationService.check_reputation
    except Exception:
        mods["ip_rep"] = None

    try:
        from json_enforcer.services import JsonEnforcerService
        mods["json_validate"] = JsonEnforcerService.validate_payload
    except Exception:
        mods["json_validate"] = None

    try:
        from ai_behaviour.services import BehaviourProfiler
        mods["log_req"] = BehaviourProfiler.log_request
        mods["is_anom"] = BehaviourProfiler.detect_anomaly
    except Exception:
        mods["log_req"] = None
        mods["is_anom"] = None

    try:
        from alert_blocking.services import AlertService, BlockingService
        mods["alert"] = AlertService
        mods["block"] = BlockingService
    except Exception:
        mods["alert"] = None
        mods["block"] = None

    return mods


MODULES = _safe_imports()


class DecisionProxyMiddleware(MiddlewareMixin):
    """
    Transparent reverse-proxy + decision engine.
    Intercepts ALL requests (except admin/static) and:
      - runs TLS/ASN/IPRep/JSON/Behaviour checks
      - consults blocklist
      - aggregates score, blocks or allows
      - logs to DB
      - forwards to backend if allowed
    """

    def process_request(self, request):
        path = request.get_full_path()
        cache_enabled = bool(getattr(settings, "ENABLE_BACKEND_CACHE", True))
        redis_client = RedisClientSingleton.get_client()
        if redis_client is None:
            cache_enabled = False

        
        # Skip admin, static, DRF browsable assets, etc (tweak as needed)
        if (
            path == "/"   
            or path.startswith("/admin")
            or path.startswith("/static")
            or path.startswith("/__debug__")
            or path.startswith("/login")
            or path.startswith("/accounts/login")
            or path.startswith("/ops")
            or path.startswith("/logout")
            or path.startswith("/tls")
            or path.startswith("/healthz")
            or path.startswith("/readyz")
            or path.startswith("/demo")
        ):
            return None

        # Extract client IP
        client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")) or ""
        body = request.body or b""
        
        # === 0) Extract x-target-id header and validate service
        target_id = request.headers.get("x-target-id")
        if not target_id:
            self._log(client_ip, path, request.method, len(body), 0, "block", "missing_target_id")
            return JsonResponse({
                "error": "Missing required header", 
                "detail": "x-target-id header is required"
            }, status=400)
        
        # Validate UUID format
        try:
            import uuid
            uuid.UUID(target_id)
        except ValueError:
            self._log(client_ip, path, request.method, len(body), 0, "block", "invalid_target_id_format")
            return JsonResponse({
                "error": "Invalid target ID format", 
                "detail": "x-target-id must be a valid UUID"
            }, status=400)
        
        # Lookup service by UUID
        if not Service:
            self._log(client_ip, path, request.method, len(body), 0, "block", "service_model_unavailable")
            return JsonResponse({
                "error": "Service unavailable", 
                "detail": "Service routing is not available"
            }, status=503)
        
        try:
            # Get MAX_SERVICES from environment variable, default to 10
            max_services = int(os.getenv('MAX_SERVICES', '10'))
            
            # First, try to get the service by target_id
            try:
                # 1) Ambil service dari cache (Redis → fallback LRU memory → DB)
                service_data = get_service_cached(target_id)
                if not service_data:
                    self._log(client_ip, path, request.method, len(body), 0, "block", "target_service_not_found")
                    return JsonResponse({
                        "error": "Target service not found",
                        "detail": f"No service found with ID: {target_id}"
                    }, status=404)

                # 2) Ambil daftar allowed services dari cache
                allowed_service_ids = get_allowed_service_ids(max_services)

                if service_data["id"] not in allowed_service_ids:
                    self._log(client_ip, path, request.method, len(body), 0, "block", "service_not_in_allowed_limit")
                    return JsonResponse({
                        "error": "Service access denied",
                        "detail": f"Service {target_id} is not within the allowed service limit (MAX_SERVICES: {max_services})"
                    }, status=403)

                # 3) Target backend dari hasil cache
                target_backend = service_data["target_base_url"]

            except ValueError as e:
                logger.error(f"Invalid MAX_SERVICES value: {e}")
                self._log(client_ip, path, request.method, len(body), 0, "block", "invalid_max_services_config")
                return JsonResponse({
                    "error": "Configuration error",
                    "detail": "Invalid MAX_SERVICES configuration"
                }, status=500)
            except Exception as e:
                logger.error(f"Error looking up service {target_id}: {e}")
                self._log(client_ip, path, request.method, len(body), 0, "block", "service_lookup_error")
                return JsonResponse({
                    "error": "Service lookup error",
                    "detail": "Unable to determine target service"
                }, status=503)
            
        except ValueError as e:
            logger.error(f"Invalid MAX_SERVICES value: {e}")
            self._log(client_ip, path, request.method, len(body), 0, "block", "invalid_max_services_config")
            return JsonResponse({
                "error": "Configuration error", 
                "detail": "Invalid MAX_SERVICES configuration"
            }, status=500)
        except Exception as e:
            logger.error(f"Error looking up service {target_id}: {e}")
            self._log(client_ip, path, request.method, len(body), 0, "block", "service_lookup_error")
            return JsonResponse({
                "error": "Service lookup error", 
                "detail": "Unable to determine target service"
            }, status=503)
        
        # === 0) Whitelist check
        # allow_ips = getattr(settings, "ALLOW_IPS", [])
        # if client_ip in allow_ips:
        #     return None  #

        def build_cache_key() -> str:
            # Use method, path (includes query), selected headers, and body hash
            # Avoid using volatile headers (Host, Connection, etc.)
            key_parts = {
                "m": request.method,
                "p": path,
                "ct": request.headers.get("Content-Type", ""),
                "ac": request.headers.get("Accept", ""),
                "tid": target_id,  # Include target ID in cache key
            }
            body_bytes = body or b""
            body_hash = hashlib.sha256(body_bytes).hexdigest() if body_bytes else "no-body"
            key_raw = json.dumps(key_parts, sort_keys=True, separators=(",", ":")) + "|" + body_hash
            return f"ritapi:backend_resp:{hashlib.sha256(key_raw.encode('utf-8')).hexdigest()}"
        
        cache_key = build_cache_key()
        if cache_enabled and redis_client is not None:
            try:
                cached = redis_client.get(cache_key)
                print("Cached: ", cached)
            except Exception as e:
                print("Redis GET failed: %s", e)
                cached = None
                cache_enabled = False
            if cached:
                try:
                    status_code, hdrs, content = pickle.loads(cached)
                    response = HttpResponse(content, status=status_code)
                    for k, v in hdrs.items():
                        if k.lower() not in ("content-encoding", "transfer-encoding", "connection"):
                            response[k] = v
                    response["X-Cache-Status"] = "hit"
                    response["X-Target-Service"] = str(service_data["uuid"])
                    self._log(client_ip, path, request.method, len(body), score, decision, reason)
                    return response
                except Exception as e:
                    logger.warning("Redis cache deserialize failed: %s", e)
        
        allow_ips = getattr(settings, "ALLOW_IPS", [])
        if client_ip in allow_ips:
            
            try:
                url = f"{target_backend}{path}"
                headers = dict(request.headers)
                headers.pop("Host", None)

                resp = requests.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=10,
                )

                response = HttpResponse(resp.content, status=resp.status_code)
                for k, v in resp.headers.items():
                    if k.lower() not in ("content-encoding", "transfer-encoding", "connection"):
                        response[k] = v
                response["X-Target-Service"] = str(service_data["uuid"])
                return response
            except Exception as e:
                return JsonResponse({"error": "backend_unreachable", "detail": str(e)}, status=502)
        
        # === 1) TLS check (cached DB lookup)
        tls_valid = True
        try:
            from tls_analyzer.services import TlsAnalyzerService
            host = request.headers.get("Host", "localhost")
            tls_cache_key = f"ritapi:tls:{host}"
            tls_record = None
            if redis_client:
                try:
                    cached_tls = redis_client.get(tls_cache_key)
                    if cached_tls:
                        tls_record = json.loads(cached_tls)
                except Exception:
                    pass

            if not tls_record:
                # kalau belum ada di cache → analyze
                tls_record = TlsAnalyzerService.get_or_analyze_tls(host)
                if tls_record and redis_client:
                    tls_record_to_dict = TlsAnalyzerService.tls_record_to_dict(tls_record)
                    try:
                        redis_client.setex(tls_cache_key, ASN_TLS_CACHE_TTL, json.dumps(tls_record_to_dict))
                    except Exception:
                        pass
                       
            if tls_record is None:
                tls_valid = True
                if MODULES["alert"]:
                    MODULES["alert"].create_alert(
                        "TLS_ANALYZER_ERROR",
                        request.META.get("REMOTE_ADDR", ""),
                        f"TLS analysis failed for host={host}",
                        "medium"
                    )
        except Exception as e:
            tls_valid = True  # fallback biar nggak nge-block request


        # === 2) ASN lookup
        asn_trust = 0
        if MODULES["lookup_asn"]:
            try:
                asn_cache_key = f"ritapi:asn:{client_ip}"
                asn_obj = None
                if redis_client:
                    try:
                        cached_asn = redis_client.get(asn_cache_key)
                        if cached_asn:
                            asn_obj = json.loads(cached_asn)
                    except Exception:
                        pass
                if not asn_obj:
                    asn_obj = MODULES["lookup_asn"](client_ip)
                    if asn_obj and redis_client:
                        try:
                            asn_obj_dict = {
                                "ip_address": getattr(asn_obj, "ip_address", None),
                                "asn_number": getattr(asn_obj, "asn_number", None),
                                "asn_description": getattr(asn_obj, "asn_description", None),
                                "trust_score": getattr(asn_obj, "trust_score", 0),
                                "is_latest": getattr(asn_obj, "is_latest", False),
                                "created_at": getattr(asn_obj, "created_at", None).isoformat() if getattr(asn_obj, "created_at", None) else None,
                            }
                            redis_client.setex(asn_cache_key, ASN_TLS_CACHE_TTL, json.dumps(asn_obj_dict))
                        except Exception as e:
                            logger.error(f"Error caching ASN : {e}")
                            print("ASN cache failed:", e)
                # support both model instance and dict
                if asn_obj:
                    asn_trust = getattr(asn_obj, "trust_score", 0) if hasattr(asn_obj, "trust_score") else asn_obj.get("trust_score", 0)
                # 🚨 Alert jika ASN trust score < -2
                if asn_trust < -2 and MODULES["alert"]:
                    MODULES["alert"].create_alert(
                        alert_type="ASN_SUSPICIOUS",
                        ip_address=client_ip,
                        detail=f"ASN trust score low ({asn_trust}) for IP {client_ip}",
                        severity="medium"
                    )
                if MODULES["block"]:
                    MODULES["block"].soft_block_ip(
                        ip_address=client_ip,
                        reason=f"ASN suspicious (score {asn_trust})",
                        severity="medium"
                    )
            except Exception:
                asn_trust = 0

        # === 3) IP reputation
        iprep_score = 0
        if MODULES["ip_rep"]:
            try:
                rep = MODULES["ip_rep"](client_ip)
                iprep_score = getattr(rep, "reputation_score", 0) if hasattr(rep, "reputation_score") else rep.get("reputation_score", rep.get("score", 0))
            except Exception:
                iprep_score = 0

        # === 4) JSON validation (only for JSON-ish requests)
        json_valid = True
        if MODULES["json_validate"]:
            try:
                payload = None
                if request.content_type and "application/json" in request.content_type.lower():
                    try:
                        payload = json.loads(body.decode("utf-8") or "{}")
                    except Exception:
                        # JSON corrupt → langsung block di sini
                        decision, reason = "block", "malformed_json"
                        self._log(client_ip, path, request.method, len(body), 0, decision, reason)
                        
                        # optional: block IP + alert
                        if MODULES["block"]:
                            MODULES["block"].block_ip(client_ip, reason="Malformed JSON", severity="high")
                        if MODULES["alert"]:
                            MODULES["alert"].create_alert("BLOCKED", client_ip, "Malformed JSON", "high")

                        return JsonResponse({"error": "Malformed JSON"}, status=400)

                if payload is not None:
                    vres = MODULES["json_validate"](path, payload)
                    json_valid = bool(vres.get("valid", True))
                    if not json_valid:
                        decision, reason = "alert", "json_schema_invalid"
                        self._log(client_ip, path, request.method, len(body), 0, decision, reason)

                        if MODULES["alert"]:
                            MODULES["alert"].create_alert("JSON SCHEMA VALIDATION FAILED", client_ip, f"Invalid JSON schema: {vres.get('message', '')}", "medium")
                        return JsonResponse({"error": "JSON SCHEMA VALIDATION FAILED"}, status=400)
            except Exception:
                json_valid = True  # fallback



        # === 5) Behaviour logging + anomaly
        anomalous = False
        if MODULES["log_req"]:
            try:
                MODULES["log_req"](
                    ip_address=client_ip,
                    endpoint=path,
                    method=request.method,
                    payload_size=len(body),
                    user_agent=request.headers.get("User-Agent", ""),
                    status_code=0,  # unknown yet
                    response_time_ms=0.0,  # unknown yet
                )
            except Exception:
                pass
        if MODULES["is_anom"]:
            try:
                anomalous = bool(MODULES["is_anom"](client_ip))
            except Exception:
                anomalous = False

        # === 6) Blocklist check
        already_blocked = False
        if MODULES["block"]:
            try:
                already_blocked = MODULES["block"].is_blocked(client_ip)
            except Exception:
                already_blocked = False

        # === Aggregate score
        score = float(asn_trust) + float(iprep_score)
        if not json_valid:
            score -= 5
        if not tls_valid:
            score -= 1
        if anomalous:
            score -= 4

        # Default decision
        decision, reason = "allow", "ok"

        # If on blocklist → block
        if already_blocked:
            decision, reason = "block", "already_blocked"
            self._log(client_ip, path, request.method, len(body), score, decision, reason)
            return JsonResponse({"error": "Blocked by blocklist"}, status=403)

        # Score-based block
        if score < -4:
            decision, reason = "block", "score_too_low"
            if MODULES["block"]:
                try:
                    MODULES["block"].block_ip(client_ip, reason="Score too low", severity="high")
                except Exception:
                    pass
            if MODULES["alert"]:
                try:
                    MODULES["alert"].create_alert("BLOCKED", client_ip, "Auto block by decision engine", "high")
                except Exception:
                    pass
            self._log(client_ip, path, request.method, len(body), score, decision, reason)

            return JsonResponse({"error": "Blocked by RITAPI", "score": score}, status=403)

        # === Forward to backend (with Redis caching)
        try:
            headers = dict(request.headers)
            headers.pop("Host", None)

            resp = requests.request(
                method=request.method,
                url=f"{target_backend}{path}",
                headers=headers,
                data=body,
                timeout=10,
            )

            response = HttpResponse(resp.content, status=resp.status_code)
            forwarded_headers = {}
            for k, v in resp.headers.items():
                if k.lower() not in ("content-encoding", "transfer-encoding", "connection"):
                    response[k] = v
                    forwarded_headers[k] = v

            # Add target service info to response headers
            response["X-Target-Service"] = str(service_data["uuid"])
            response["X-Target-URL"] = target_backend

            if cache_enabled and redis_client is not None and request.method in ("GET", "HEAD") and resp.status_code == 200:
                try:
                    ttl = int(getattr(settings, "BACKEND_RESPONSE_CACHE_TTL", 30))
                    payload = pickle.dumps((resp.status_code, forwarded_headers, resp.content))
                    redis_client.setex(cache_key, ttl, payload)
                    response["X-Cache-Status"] = "stored"
                except Exception as e:
                    logger.warning("Redis SETEX failed: %s", e)
                    response["X-Cache-Status"] = "store_failed"
            else:
                if not cache_enabled or redis_client is None:
                    response["X-Cache-Status"] = "disabled"
                elif request.method not in ("GET", "HEAD"):
                    response["X-Cache-Status"] = "skipped_method"
                elif resp.status_code != 200:
                    response["X-Cache-Status"] = "skipped_status"

            self._log(client_ip, path, request.method, len(body), score, decision, reason)
            return response

        except Exception as e:
            decision, reason = "block", f"backend_error: {e}"
            if MODULES["alert"]:
                try:
                    MODULES["alert"].create_alert("BACKEND_ERROR", client_ip, str(e), "critical")
                except Exception:
                    pass
            self._log(client_ip, path, request.method, len(body), score, decision, reason)
            return JsonResponse({"error": "backend_unreachable", "detail": str(e)}, status=502)

    @staticmethod
    def _log(ip, path, method, size, score, decision, reason):
        try:
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                method=method,
                body_size=size,
                score=score,
                decision=decision,
                reason=reason
            )
        except Exception:
            # never fail the request because of logging
            pass

import logging
import ssl
import socket
from OpenSSL import crypto
from django.utils import timezone
from datetime import timezone as dt_timezone, timedelta
from .models import TlsAnalyzer

logger = logging.getLogger(__name__)
class TlsAnalyzerService:
    
    @staticmethod
    def format_issuer(issuer):
        try:
            return ", ".join(f"{name}={value}" for rdn in issuer for (name, value) in rdn)
        except Exception:
            return str(issuer)

    @staticmethod
    def analyze_tls(domain: str, port: int = 443, timeout: int = 5) -> TlsAnalyzer:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(timeout)
                s.connect((domain, port))
                cert_bin = s.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)

                subject = dict(cert.get_subject().get_components())
                issuer = dict(cert.get_issuer().get_components())
                expiry_raw = cert.get_notAfter().decode("utf-8")

                expires_naive = timezone.datetime.strptime(expiry_raw, "%Y%m%d%H%M%SZ")
                expires = timezone.make_aware(expires_naive, dt_timezone.utc)

                record = TlsAnalyzer.objects.create(
                    ip_address=s.getpeername()[0],
                    hostname=domain,
                    subject=subject.get(b"CN", b"").decode(),
                    issuer=issuer.get(b"O", b"").decode(),
                    expires=expires,
                    serial_number=str(cert.get_serial_number()),
                    is_valid=timezone.now() < expires,
                    last_checked=timezone.now(),
                )
                return record

        except Exception as e:
            logger.error(f"TLS analysis failed for {domain}: {e}")
            return None
        
    @staticmethod
    def get_or_analyze_tls(domain: str, max_age_hours: int = 24) -> TlsAnalyzer:
        """
        Ambil TLS info dari DB jika masih fresh (< max_age_hours), 
        kalau tidak baru analisis ulang.
        """
        cutoff = timezone.now() - timedelta(hours=max_age_hours)
        record = TlsAnalyzer.objects.filter(
            hostname=domain,
            last_checked__gte=cutoff
        ).order_by("-last_checked").first()

        if record:
            return record

        return TlsAnalyzerService.analyze_tls(domain)
    

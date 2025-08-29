import logging
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail,BadHeaderError
from .models import Alert, BlockedIP
from datetime import timedelta
import smtplib


logger = logging.getLogger("alerts")
class AlertService:
    @staticmethod
    def create_alert(alert_type: str, ip_address: str, detail: str, severity: str = "low"):
        """
        Buat alert baru dan kirim email notifikasi via Mailtrap.
        """
        alert = Alert.objects.create(
            alert_type=alert_type,
            ip_address=ip_address,
            detail=detail,
            severity=severity,
        )

        # kirim email via Mailtrap (SMTP config ada di settings.py)
        subject = f"[{severity.upper()}] Alert: {alert_type}"
        message = f"""
        Alert Detected!

        Type     : {alert_type}
        IP       : {ip_address}
        Severity : {severity}
        Detail   : {detail}
        Time     : {alert.timestamp}
        """
        if severity.lower() in ["high", "critical"]:
            try:
                send_mail(
                    subject,
                    message,
                    getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@waf.local"),
                    [getattr(settings, "ALERT_EMAIL_TO", "admin@example.com")],
                    fail_silently=False,
                )
            except BadHeaderError as e:
                logger.error("Invalid header in alert email: %s", str(e), exc_info=True)
            except smtplib.SMTPException as e:
                logger.error("SMTP error while sending alert email: %s", str(e), exc_info=True)
            except Exception as e:
                logger.exception("Unexpected error while sending alert email: %s", str(e))
        else:
            logger.info("Alert severity '%s' ignored; email not sent.", severity)
        return alert


class BlockingService:
    @staticmethod
    def block_ip(ip_address: str, reason: str, severity: str = "low", duration_minutes: int = None):
        """
        Blokir IP. Jika duration_minutes diberikan, set expires_at.
        """
        expires_at = None
        if duration_minutes:
            expires_at = timezone.now() + timedelta(minutes=duration_minutes)

        blocked, created = BlockedIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                "reason": reason,
                "severity": severity,
                "active": True,
                "expires_at": expires_at,
            },
        )
        return blocked

    @staticmethod
    def unblock_ip(ip_address: str):
        """
        Hapus blokir IP (set active=False).
        """
        try:
            blocked = BlockedIP.objects.get(ip_address=ip_address)
            blocked.active = False
            blocked.save()
            return blocked
        except BlockedIP.DoesNotExist:
            return None

    @staticmethod
    def is_blocked(ip_address: str):
        """
        Cek apakah IP masih diblokir (dan belum expired).
        """
        try:
            blocked = BlockedIP.objects.get(ip_address=ip_address, active=True)
            if blocked.expires_at and blocked.expires_at < timezone.now():
                # auto unblock jika sudah expired
                blocked.active = False
                blocked.save()
                return False
            return True
        except BlockedIP.DoesNotExist:
            return False
        
    @staticmethod
    def soft_block_ip(ip_address: str, reason: str, severity: str = "medium"):
        """
        Soft block: hanya tandai IP dengan active=False.
        Tidak benar-benar memblokir request.
        """
        blocked, created = BlockedIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                "reason": reason,
                "severity": severity,
                "active": False,   # ✅ bedanya di sini
                "expires_at": None,
            },
        )
        return blocked

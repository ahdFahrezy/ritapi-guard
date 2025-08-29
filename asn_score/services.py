from ipwhois import IPWhois
from django.utils import timezone
from .models import AsnInfo, AsnTrustConfig
import socket



class AsnScoreService:
    @classmethod
    def get_trust_score(cls, asn_number: str) -> float:
        """
        Cari trust score dari DB berdasarkan ASN.
        Jika tidak ketemu, auto-buat config baru dengan score 0
        """
        try:
            config = AsnTrustConfig.objects.get(asn_number=asn_number)
            return config.score
        except AsnTrustConfig.DoesNotExist:
            AsnTrustConfig.objects.create(
                asn_number=asn_number,
                name=asn_number,   # default: pakai nomor ASN
                score=0
            )
            return 0

    @staticmethod
    def lookup_asn(ip_address: str):
        try:
            whois_server = "whois.cymru.com"
            port = 43
            query = f"begin\n{ip_address}\nend\n"

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((whois_server, port))
                s.send(query.encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

            decoded = response.decode().strip().splitlines()

            if len(decoded) >= 2:
                parts = decoded[-1].split("|")
                asn_number = parts[0].strip()
                asn_description = parts[-1].strip()
            else:
                asn_number = "UNKNOWN"
                asn_description = "UNKNOWN"

        except Exception as e:
            asn_number = "UNKNOWN"
            asn_description = str(e)

        # ✅ Buat atau ambil konfigurasi ASN
        config, created = AsnTrustConfig.objects.get_or_create(
            asn_number=asn_number,
            defaults={"name": asn_description, "score": 0}
        )

        AsnInfo.objects.filter(ip_address=ip_address, is_latest=True).update(is_latest=False)
        # ✅ Simpan hasil lookup ke ASN Info
        record = AsnInfo.objects.create(
            ip_address=ip_address,
            asn_number=asn_number,
            asn_description=asn_description,
            trust_score=config.score,
            is_latest=True
        )

        return record
import requests
from django.utils import timezone
from .models import IpReputation


class IpReputationService:
    # --- threat feeds (bisa di-cache agar tidak selalu request per call) ---
    TOR_URL = "https://check.torproject.org/torbulkexitlist"
    FIREHOL_URL = "https://iplists.firehol.org/files/firehol_level1.netset"
    EMERGING_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

    # cache feed supaya tidak hit API setiap kali dipanggil
    tor_list = set()
    firehol_list = set()
    emerging_list = set()
    feeds_loaded = False

    @classmethod
    def load_threat_feeds(cls):
        """Load threat feeds online sekali lalu cache ke memory"""
        def load_feed(url):
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.strip().splitlines()
                    return set(line.strip() for line in lines if line and not line.startswith("#"))
            except Exception as e:
                print(f"Error loading feed {url}: {e}")
            return set()

        if not cls.feeds_loaded:
            cls.tor_list = load_feed(cls.TOR_URL)
            cls.firehol_list = load_feed(cls.FIREHOL_URL)
            cls.emerging_list = load_feed(cls.EMERGING_URL)
            cls.feeds_loaded = True

    @staticmethod
    def check_reputation(ip_address: str):
        """
        Cek reputasi IP terhadap threat feeds (tanpa ASN dulu).
        """

        try:
            # Pastikan threat feed sudah dimuat
            IpReputationService.load_threat_feeds()

            # Ambil data IP dari ipapi (opsional, bisa dipakai untuk metadata)
            url = f"https://ipapi.co/{ip_address}/json/"
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                raise Exception(f"API Error {resp.status_code}")

            data = resp.json()
            isp = data.get("org", "UNKNOWN")
            country = data.get("country_name", "UNKNOWN")
            asn = data.get("asn", "")

            # --- RULE REPUTATION ---
            reputation_score = 0
            is_tor = False
            sources = []

            # Allowlist manual
            allowlist = ["1.1.1.1"]
            if ip_address in allowlist:
                reputation_score += 1
                sources.append("ALLOWLIST")

            # Tor check
            if ip_address in IpReputationService.tor_list:
                reputation_score -= 2
                is_tor = True
                sources.append("TOR")

            # Malware check (emerging threats)
            if ip_address in IpReputationService.emerging_list:
                reputation_score -= 3
                sources.append("EMERGING_THREATS")

            # Blacklist check (firehol level1)
            if ip_address in IpReputationService.firehol_list:
                reputation_score -= 5
                sources.append("FIREHOL")

            scores = {
                "raw": data,
                "isp": isp,
                "country": country,
                "asn": asn,
                "is_tor": is_tor,
                "ip_reputation_score": reputation_score,
                "sources": sources,
            }

        except Exception as e:
            isp, country, asn, is_tor = "UNKNOWN", "UNKNOWN", "UNKNOWN", False
            reputation_score = 0
            scores = {"error": str(e)}

        # ✅ simpan ke DB
        record, created = IpReputation.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                "scores": scores,
                "reputation_score": reputation_score,
                "isp": isp,
                "country": country,
                "is_tor": is_tor,
                "timestamp": timezone.now(),
            }
        )
        return record
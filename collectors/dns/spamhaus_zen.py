from collectors.base.dns_collector import DNSCollector
from config.settings import USE_MOCK_API
from utils.ip import reverse_ipv4
from utils.verdict import Verdict


class SpamhausZenCollector(DNSCollector):
    name = "spamhaus_zen"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "zen.spamhaus.org"

    ENDPOINT = "/lookup"

    RETURN_CODES  = {
        "127.0.0.2": "SBL - Spamhaus SBL data",
        "127.0.0.3": "SBL - Spamhaus CSS data",
        "127.0.0.4": "XBL - Spamhaus CBL data",
        "127.0.0.9": "PBL - Spamhaus DROP data",
        "127.0.0.10": "PBL - ISP maintained",
        "127.0.0.11": "PBL - Spamhaus maintained",
    }

    def collect(self, address: str) -> dict:
        if USE_MOCK_API:
            r = self.session.get(
                self.url(),
                params={"ip": address},
            )

            if not r.ok:
                return {"listed": False, "codes": [], "lists": [],}

            return r.json()

        query = f"{reverse_ipv4(address)}.{self.BASE_URL}"
        records = self.resolve_dns(query)

        return {
            "listed": bool(records),
            "codes": records,
            "lists": [self.RETURN_CODES.get(r, "unknown") for r in records],
        }

    def classify(self, data: dict):
        if not data["listed"]:
            return Verdict.BENIGN

        codes = set(data["codes"])

        malicious_codes = {
            "127.0.0.2",  # SBL
            "127.0.0.3",  # CSS
            "127.0.0.4",  # XBL
            "127.0.0.9",  # DROP
        }

        suspicious_codes = {
            "127.0.0.10",  # PBL ISP maintained
            "127.0.0.11",  # PBL Spamhaus maintained
        }

        if codes & malicious_codes:
            return Verdict.MALICIOUS

        if codes & suspicious_codes:
            return Verdict.SUSPICIOUS

        return Verdict.SUSPICIOUS

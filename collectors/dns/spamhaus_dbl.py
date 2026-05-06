from collectors.base.dns_collector import DNSCollector
from config.settings import USE_MOCK_API
from utils.verdict import Verdict


class SpamhausDBLCollector(DNSCollector):
    name = "spamhaus_dbl"

    supports_domain = True
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = "dbl.spamhaus.org"

    ENDPOINT = "/lookup"

    RETURN_CODES = {
        "127.0.1.2": "spam domain",
        "127.0.1.4": "phishing domain",
        "127.0.1.5": "malware domain",
        "127.0.1.6": "botnet C2",
        "127.0.1.102": "abused legit spam",
        "127.0.1.103": "abused spammed redirector domain",
        "127.0.1.104": "abused legit phish",
        "127.0.1.105": "abused legit malware",
        "127.0.1.106": "abused legit botnet C2",
    }

    def collect(self, address: str) -> dict:
        if USE_MOCK_API:
            r = self.session.get(
                self.url(),
                params={"domain": address},
            )

            if not r.ok:
                return {
                    "listed": False,
                    "codes": [],
                    "lists": [],
                }

            return r.json()

        query = f"{address}.{self.BASE_URL}"

        answers = self.resolve_dns(query)

        return {
            "listed": bool(answers),
            "codes": answers,
            "lists": [
                self.RETURN_CODES.get(code, "UNKNOWN")
                for code in answers
            ],
        }

    def classify(self, data: dict) -> Verdict:
        if not data["listed"]:
            return Verdict.BENIGN

        return Verdict.MALICIOUS

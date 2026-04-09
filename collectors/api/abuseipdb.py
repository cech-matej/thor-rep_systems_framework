from collectors.base.api_collector import APICollector
from config.settings import ABUSEIPDB_API_KEY
from utils.verdict import Verdict


class AbuseIPDBCollector(APICollector):
    name = "abuseipdb"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = True

    BASE_URL = "https://api.abuseipdb.com"
    ENDPOINT = "/api/v2/check"

    def __init__(self):
        super().__init__()
        self.api_key = ABUSEIPDB_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "Key": self.api_key,
        }

        response = self.session.get(
            self.url(),
            headers=headers,
            params={"ipAddress": address},
        )

        data = response.json().get("data", {}) if response.ok else {}

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", -1),
            "is_whitelisted": data.get("isWhitelisted"),
            "is_tor": data.get("isTor"),
            "total_reports": data.get("totalReports", -1),
        }

    def classify(self, data: dict) -> Verdict:
        score = data.get("abuse_confidence_score", -1)

        if score < 0:
            return Verdict.NO_DATA
        elif score < 10:
            return Verdict.BENIGN
        elif score < 50:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS

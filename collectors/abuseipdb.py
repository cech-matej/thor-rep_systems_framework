from collectors.base import BaseCollector
from config.settings import ABUSEIPDB_API_KEY
from utils.ip import is_ipv4


class AbuseIPDBCollector(BaseCollector):
    name = "abuseipdb"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = True

    BASE_URL = "https://api.abuseipdb.com"
    ENDPOINT = "/api/v2/check"

    # # Visualization
    # vis_labels = ["Benign", "Probably benign", "Probably malicious", "Malicious"]
    # vis_colors = ["#2ca02c", "#98df8a", "#ffbb78", "#d62728"]

    def __init__(self):
        super().__init__()
        self.api_key = ABUSEIPDB_API_KEY

        # # Set classification function
        # self.vis_classify = self._abuseipdb_classify

    def collect(self, address: str) -> dict:

        # if not is_ipv4(address):
        #     return {}

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


    # # ----- Visualization Classification -----
    # def _abuseipdb_classify(self, data: list) -> list[int]:
    #     def count(lower: int, upper: int) -> int:
    #         return sum(
    #             1 for item in data
    #             if
    #             lower <= item.get("data_first_ipv4", {}).get("data", {}).get("abuse_confidence_score", -1) <= upper
    #         )
    #
    #     return [
    #         count(0, 0),
    #         count(1, 19),
    #         count(20, 49),
    #         count(50, 100),
    #     ]

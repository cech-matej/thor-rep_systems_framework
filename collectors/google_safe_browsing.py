from collectors.base import BaseCollector
from config.settings import GOOGLE_SAFE_BROWSING_API_KEY
from utils.ip import is_ipv6
from utils.verdict import Verdict


class GoogleSafeBrowsingCollector(BaseCollector):
    name = "google_safe_browsing"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False  # original code skips IPv6

    BASE_URL = f"https://safebrowsing.googleapis.com"
    ENDPOINT = "/v4/threatMatches:find"  # API key will be added in collect() as query param

    def __init__(self):
        super().__init__()
        self.api_key = GOOGLE_SAFE_BROWSING_API_KEY

    def collect(self, address: str) -> dict:
        if is_ipv6(address):
            return {}

        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }

        post_data = {
            "client": {
                "clientId": "domrad-bp",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "THREAT_TYPE_UNSPECIFIED",
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ALL_PLATFORMS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": address}]
            }
        }

        url = f"{self.url()}?key={self.api_key}"

        response = self.session.post(url, headers=headers, json=post_data)

        if response.ok:
            results = response.json()
            counts = {
                "unspecified_cnt": 0,
                "malware_cnt": 0,
                "social_engineering_cnt": 0,
                "unwanted_software_cnt": 0,
                "potentially_harmful_cnt": 0
            }

            for match in results.get("matches", []):
                threat_type = match.get("threatType")
                if threat_type == "THREAT_TYPE_UNSPECIFIED":
                    counts["unspecified_cnt"] += 1
                elif threat_type == "MALWARE":
                    counts["malware_cnt"] += 1
                elif threat_type == "SOCIAL_ENGINEERING":
                    counts["social_engineering_cnt"] += 1
                elif threat_type == "UNWANTED_SOFTWARE":
                    counts["unwanted_software_cnt"] += 1
                elif threat_type == "POTENTIALLY_HARMFUL_APPLICATION":
                    counts["potentially_harmful_cnt"] += 1

            return counts
        else:
            return {
                "unspecified_cnt": -1,
                "malware_cnt": -1,
                "social_engineering_cnt": -1,
                "unwanted_software_cnt": -1,
                "potentially_harmful_cnt": -1
            }

    def classify(self, data: dict) -> Verdict:
        unspecified_cnt = data.get("unspecified_cnt", -1)
        malware_cnt = data.get("malware_cnt", -1)
        social_engineering_cnt = data.get("social_engineering_cnt", -1)
        unwanted_software_cnt = data.get("unwanted_software_cnt", -1)
        potentially_harm_cnt = data.get("potentially_harmful_cnt", -1)

        # If at least one count is -1, then all counts are -1 => no data for this entity
        if malware_cnt < 0:
            return Verdict.NO_DATA

        sum_cnt = unspecified_cnt + malware_cnt + social_engineering_cnt + unwanted_software_cnt + potentially_harm_cnt

        if sum_cnt == 0:
            return Verdict.BENIGN
        elif sum_cnt == 1:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS
from collectors.base import BaseCollector
from config.settings import THREATFOX_API_KEY
from utils.ip import is_ipv6
from utils.verdict import Verdict


class ThreatFoxCollector(BaseCollector):
    name = "threatfox"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://threatfox-api.abuse.ch"
    ENDPOINT = "/api/v1"  # target sent in POST body

    def __init__(self):
        super().__init__()
        self.api_key = THREATFOX_API_KEY

    def collect(self, address: str) -> dict:
        if is_ipv6(address):
            return {}

        headers = {
            "accept": "application/json",
            "Auth-Key": self.api_key,
        }

        post_data = {
            "query": "search_ioc",
            "search_term": address,
            "exact_match": False,
        }

        response = self.session.post(f"{self.url()}", headers=headers, json=post_data)

        threat_type = ""
        malware = ""
        confidence_level = ""
        tags = []

        if response.ok:
            results = response.json()
            if results.get("query_status") == "ok" and "data" in results:
                data_list = results["data"]
                if isinstance(data_list, list) and len(data_list) > 0:
                    data = data_list[0]  # take first item
                    threat_type = data.get("threat_type", "")
                    malware = data.get("malware", "")
                    confidence_level = data.get("confidence_level", "")
                    tags = data.get("tags", [])

        return {
            "threat_type": threat_type,
            "malware": malware,
            "confidence_level": confidence_level,
            "tags": tags,
        }

    def classify(self, data: dict) -> Verdict:
        confidence = data.get("confidence_level", -1)

        if confidence < 0:
            return Verdict.NO_DATA
        elif confidence < 10:
            return Verdict.BENIGN
        elif confidence < 0.5:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS

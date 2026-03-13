from collectors.base import BaseCollector
from config.settings import VIRUSTOTAL_API_KEY
from utils.ip import is_ipv4, is_ipv6


class VirusTotalCollector(BaseCollector):
    name = "virustotal"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = True

    BASE_URL = "https://www.virustotal.com"

    ENDPOINT_IP = "/api/v3/ip_address/"
    ENDPOINT_DN = "/api/v3/domains/"

    def __init__(self):
        super().__init__()
        self.api_key = VIRUSTOTAL_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }

        if is_ipv4(address) or is_ipv6(address):
            self.ENDPOINT = self.ENDPOINT_IP
            url = f"{self.url()}{address}"
        else:
            self.ENDPOINT = self.ENDPOINT_DN
            url = f"{self.url()}{address}"

        response = self.session.get(url, headers=headers)

        if response.ok:
            json_response = response.json()
            data = json_response.get("data")
            if data and "attributes" in data:
                attributes = data["attributes"]
                last_stats = attributes.get("last_analysis_stats", {})
                malicious = last_stats.get("malicious", -1)
                suspicious = last_stats.get("suspicious", -1)
                undetected = last_stats.get("undetected", -1)
                harmless = last_stats.get("harmless", -1)
                return {
                    "reputation": attributes.get("reputation", -1),
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                }

        return {
            "reputation": -1,
            "malicious": -1,
            "suspicious": -1,
            "undetected": -1,
            "harmless": -1,
        }
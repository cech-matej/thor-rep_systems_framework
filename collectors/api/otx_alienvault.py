import requests

from collectors.base.api_collector import APICollector
from config.settings import OTX_ALIENVAULT_API_KEY
from utils.ip import is_ipv4, is_ipv6
from utils.verdict import Verdict

class OTXAlienvaultCollector(APICollector):
    name = "otx_alienvault"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = True

    BASE_URL = "https://otx.alienvault.com"

    ENDPOINT_BASE = "/api/v1/indicators"
    ENDPOINT_IPv4 = "/IPv4/"
    ENDPOINT_IPv6 = "/IPv6/"
    ENDPOINT_DN = "/domain/"

    TYPE = "/general"

    def __init__(self):
        super().__init__()
        self.api_key = OTX_ALIENVAULT_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "X-OTX-API-KEY": self.api_key,
        }

        if is_ipv4(address):
            self.ENDPOINT = self.ENDPOINT_BASE + self.ENDPOINT_IPv4
        elif is_ipv6(address):
            self.ENDPOINT = self.ENDPOINT_BASE + self.ENDPOINT_IPv6
        else:
            self.ENDPOINT = self.ENDPOINT_BASE + self.ENDPOINT_DN

        response = requests.get(f"{self.url()}{address}{self.TYPE}", headers=headers)

        self.validate_response(response)

        if response.ok:
            json_response = response.json()

            pulse_count = json_response.get("pulse_info").get("count")
            return { "pulse_count": pulse_count }

        return {}

    def classify(self, data: dict) -> Verdict:
        pulse_count = data.get("pulse_count", 0)

        if pulse_count == 0:
            return Verdict.NO_DATA
        elif pulse_count < 3:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

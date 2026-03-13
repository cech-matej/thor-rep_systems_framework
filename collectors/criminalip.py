from collectors.base import BaseCollector
from config.settings import CRIMINALIP_API_KEY
from utils.ip import is_ipv4, is_ipv6


class CriminalIPCollector(BaseCollector):
    name = "criminalip"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False  # original code only supports IPv4

    BASE_URL = "https://api.criminalip.io"
    ENDPOINT = "/v1/asset/ip/report"  # ?ip=<address>&full=true will be added in collect

    def __init__(self):
        super().__init__()
        self.api_key = CRIMINALIP_API_KEY

    def collect(self, address: str) -> dict:
        if not is_ipv4(address):
            return {}

        headers = {
            "accept": "application/json",
            "x-api-key": self.api_key,
        }

        # build URL
        url = f"{self.url()}?ip={address}&full=true"

        response = self.session.get(url, headers=headers)

        if response.ok:
            return response.json()
        else:
            return {}
from collectors.base import BaseCollector
from config.settings import GREYNOISE_API_KEY
from utils.ip import is_ipv4


class GreyNoiseCollector(BaseCollector):
    name = "greynoise"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://api.greynoise.io"
    ENDPOINT = "/v3/community/"  # IP appended in collect()

    def __init__(self):
        super().__init__()
        self.api_key = GREYNOISE_API_KEY

    def collect(self, address: str) -> dict:
        if not is_ipv4(address):
            return {}

        headers = {
            "accept": "application/json",
            "key": self.api_key,
        }

        url = f"{self.url()}{address}"

        response = self.session.get(url, headers=headers)

        if response.ok:
            return response.json()
        else:
            return {}
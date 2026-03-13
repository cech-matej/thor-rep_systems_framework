from collectors.base import BaseCollector
from config.settings import NERD_API_KEY
from utils.ip import is_ipv4


class NerdCollector(BaseCollector):
    name = "nerd"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://nerd.cesnet.cz"
    ENDPOINT = "/nerd/api/v1/ip/"  # IP appended in collect()

    def __init__(self):
        super().__init__()
        self.api_key = NERD_API_KEY

    def collect(self, address: str) -> dict:
        if not is_ipv4(address):
            return { "reputation": -1 }

        headers = {
            "accept": "application/json",
            "Authorization": self.api_key,
        }

        url = f"{self.url()}{address}"

        response = self.session.get(url, headers=headers)

        if response.ok:
            results = response.json()
            return { "reputation": results.get("rep", -1) }
        else:
            return { "reputation": -1 }
from collectors.base.api_collector import APICollector
from config.settings import GRIFFINGUARD_API_KEY
from utils.ip import is_ipv4
from utils.verdict import Verdict


class GriffinGuardCollector(APICollector):
    name = "griffinguard"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://griffinguard.io"
    ENDPOINT = "/api/ipquery/"

    def __init__(self):
        super().__init__()
        self.api_key = GRIFFINGUARD_API_KEY

    def collect(self, address: str) -> dict:
        if not is_ipv4(address):
            return {}

        headers = {
            "accept": "application/json",
            "X-API-Key": self.api_key,
        }

        # Build URL
        url = f"{self.url()}{address}"

        response = self.session.get(url, headers=headers)

        self.validate_response(response)

        if response.ok:
            return response.json()
        else:
            return {}

    def classify(self, data: dict) -> Verdict:
        classification = data.get("classification", None)

        if classification is None:
            return Verdict.NO_DATA
        elif classification == "Unknown":
            return Verdict.NO_DATA
        elif classification == "Benign":
            return Verdict.BENIGN
        else:
            return Verdict.MALICIOUS
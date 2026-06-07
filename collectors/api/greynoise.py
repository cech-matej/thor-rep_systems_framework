from collectors.base.api_collector import APICollector
from config.settings import GREYNOISE_API_KEY
from utils.ip import is_ipv4
from utils.verdict import Verdict


class GreyNoiseCollector(APICollector):
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

        self.validate_response(response)

        if response.ok:
            return response.json()
        else:
            return {}

    def classify(self, data: dict) -> Verdict:
        classification = data.get("classification", None)

        if classification is None:
            return Verdict.NO_DATA
        elif classification == 'benign':
            return Verdict.BENIGN
        elif classification == 'unknown':
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS
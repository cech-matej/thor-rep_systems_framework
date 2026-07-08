from collectors.base.api_collector import APICollector
from config.settings import PULSEDIVE_API_KEY
from utils.verdict import Verdict


class PulsediveCollector(APICollector):
    name = "pulsedive"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = True

    BASE_URL = "https://pulsedive.com"
    ENDPOINT = "/api/info.php"  # query string added in collect()

    def __init__(self):
        super().__init__()
        self.api_key = PULSEDIVE_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
        }

        url = f"{self.url()}?key={self.api_key}&indicator={address}&pretty=1"

        response = self.session.get(url, headers=headers)

        self.validate_response(response)

        if response.ok:
            return response.json()
        else:
            return {}

    def classify(self, data: dict) -> Verdict:
        risk = data.get("risk", None)

        if risk is None or risk == "unknown":
            return Verdict.NO_DATA
        elif risk == "none":
            return Verdict.BENIGN
        elif risk in ["very low", "low"]:
            return Verdict.SUSPICIOUS

        return Verdict.MALICIOUS

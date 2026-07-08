from collectors.base.api_collector import APICollector
from config.settings import PHISHING_INITIATIVE_API_KEY
from utils.verdict import Verdict


class PhishingInitiativeCollector(APICollector):
    name = "phishing_initiative"

    supports_domain = True
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = "https://phishing-initiative.eu"
    ENDPOINT = "/api/v1/urls/lookup/?url="  # DN appended in collect()

    def __init__(self):
        super().__init__()
        self.api_key = PHISHING_INITIATIVE_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "Authorization": f"Token {self.api_key}",
        }

        url = f"{self.url()}{address}"

        response = self.session.get(url, headers=headers)

        self.validate_response(response)

        if response.ok:
            return response.json()[0]
        else:
            return {}

    def classify(self, data: dict) -> Verdict:
        classification = data.get("tag", None) if data else None

        if classification is None:
            return Verdict.NO_DATA
        elif classification == -1:
            return Verdict.BENIGN
        else:
            return Verdict.MALICIOUS
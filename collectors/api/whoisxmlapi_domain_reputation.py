import requests

from collectors.base.api_collector import APICollector
from config.settings import WHOISXML_DOMAIN_REPUTATION_API_KEY
from utils.verdict import Verdict

class WhoisXMLAPIDomainReputationCollector(APICollector):
    name = "whoisxmlapi_domain_reputation"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://domain-reputation.whoisxmlapi.com"

    ENDPOINT = "/api/v2"

    def __init__(self):
        super().__init__()
        self.api_key = WHOISXML_DOMAIN_REPUTATION_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
        }

        response = requests.get(f"{self.url()}?apiKey={self.api_key}&domainName={address}", headers=headers)

        self.validate_response(response)

        if response.ok:
            json_response = response.json()

            rep = json_response.get("reputationScore")
            return { "reputationScore": rep }

        return {}

    def classify(self, data: dict) -> Verdict:
        rep = data.get("reputationScore")

        if rep > 90:
            return Verdict.BENIGN
        elif rep > 50:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

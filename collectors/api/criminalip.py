from collectors.base.api_collector import APICollector
from config.settings import CRIMINALIP_API_KEY
from utils.ip import is_ipv4, is_ipv6
from utils.verdict import Verdict


class CriminalIPCollector(APICollector):
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

        self.validate_response(response)

        if response.ok:
            return response.json()
        else:
            return {}

    def classify(self, data: dict) -> Verdict:
        score_out = data.get("score", {}).get("outbound", None)

        if score_out is None:
            return Verdict.NO_DATA
        elif score_out == "Safe":
            return Verdict.BENIGN
        elif score_out in ["Low", "Moderate"]:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS
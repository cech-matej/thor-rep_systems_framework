from collectors.base.api_collector import APICollector
from config.settings import CLOUDFLARE_RADAR_API_KEY, CLOUDFLARE_USERID
from utils.ip import is_ipv4, is_ipv6
from utils.verdict import Verdict


class CloudflareRadarCollector(APICollector):
    name = "cloudflare_radar"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False  # Radar doesn't support IPv6 in old code

    BASE_URL = "https://api.cloudflare.com"
    ENDPOINT = f"/client/v4/accounts/{CLOUDFLARE_USERID}/urlscanner/v2/search?size=1&q="  # query string will be appended in collect()

    def __init__(self):
        super().__init__()
        self.api_key = CLOUDFLARE_RADAR_API_KEY

    def collect(self, address: str) -> dict:

        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # build target query
        if is_ipv4(address):
            query = f"page.ip:{address}"
        elif self.supports_domain and not is_ipv4(address) and not is_ipv6(address):
            query = f"page.domain:{address}"
        else:
            # IPv6 not supported
            return { "malicious": None }

        # append query to URL
        url = f"{self.url()}{query}"

        response = self.session.get(url, headers=headers)

        self.validate_response(response)

        if response.ok:
            results = response.json().get("results", [])
            mal = results[0]["verdicts"]["malicious"] if results else None
            return { "malicious": mal }
        else:
            print(response.text)
            return { "malicious": None }

    def classify(self, data: dict) -> Verdict:
        malicious = data.get("malicious", None)

        if malicious is None:
            return Verdict.NO_DATA
        elif malicious:
            return Verdict.MALICIOUS
        else:
            return Verdict.BENIGN
from collectors.base import BaseCollector


class FortiGuardCollector(BaseCollector):
    name = "fortiguard"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = True  # assume same handling for IPs

    BASE_URL = "https://www.fortiguard.com"
    ENDPOINT = "/learnmore/check-blocklist"  # POST body will supply the target

    def __init__(self):
        super().__init__()

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }

        post_data = { "url": address }

        response = self.session.post(f"{self.url()}", headers=headers, json=post_data)

        if response.ok:
            try:
                resp = response.json()
                return { "spam": resp.get("spam") }
            except Exception:
                return { "spam": None }
        else:
            return { "spam": None }
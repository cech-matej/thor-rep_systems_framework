from collectors.base.html_collector import HTMLCollector
from utils.verdict import Verdict


class ProjectHoneypotCollector(HTMLCollector):
    name = "project_honeypot"

    supports_domain = False
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://www.projecthoneypot.org"
    ENDPOINT = "/ip_"

    def __init__(self):
        super().__init__()

    def collect(self, address: str) -> dict:
        # Scrape HTML content from the provided URL
        soup = self.scrape_html(self.url() + address)

        # If scraping failed, return default "malicious" value
        if not soup:
            return { "malicious": None }

        # Check for the presence of the first <h2> tag
        h2 = soup.find("h2")

        if not h2:
            return { "malicious": None }

        # Return malicious status based on whether <h2> has child elements
        return { "malicious": bool(h2.find("a")) }

    def classify(self, data: dict) -> Verdict:
        return Verdict.NO_DATA if data.get("malicious") in { None, False } else Verdict.MALICIOUS

from bs4 import BeautifulSoup

from collectors.base.html_collector import HTMLCollector
from utils.verdict import Verdict


class URLVoid(HTMLCollector):
    name = "urlvoid"

    supports_domain = True
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = "https://www.urlvoid.com"
    ENDPOINT = "/scan/"

    def __init__(self):
        super().__init__()

    def collect(self, address: str) -> dict:
        # Scrape HTML content from the provided URL
        soup = self.scrape_html(self.url() + address)

        # If scraping failed, return default "malicious" value
        if not soup:
            return { "detection_counts": -1 }

        return { "detection_counts": self.parse_detection_counts(soup) }

    def classify(self, data: dict) -> Verdict:
        cnt = data["detection_counts"]

        if cnt < 0:
            return Verdict.NO_DATA
        elif cnt < 2:
            return Verdict.BENIGN
        elif cnt < 4:
            return Verdict.SUSPICIOUS

        return Verdict.MALICIOUS

    @staticmethod
    def parse_detection_counts(soup: BeautifulSoup) -> int:
        # Select the first table
        report_table = soup.select("table")[0] if soup.select("table") else None

        if report_table:
            # Select all rows in the table
            report_table_rows = report_table.select("tr")

            if len(report_table_rows) > 2:
                # Get the second row (index 2) and select the second td (index 1)
                detection_counts_span = report_table_rows[2].select("td")[1].select("span")

                if detection_counts_span:
                    # Get the text of the first <span> and remove non-digit characters
                    detection_text = detection_counts_span[0].get_text()

                    # Extract the numeric part from the text (e.g., "10 detections" -> 10)
                    detection_count = ''.join(filter(str.isdigit, detection_text))

                    # Return as an integer if a number was found, else return None
                    if detection_count:
                        return int(detection_count)

        return -1
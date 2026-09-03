from collectors.base.dns_collector import DNSCollector
from config.settings import USE_MOCK_API
from utils.exceptions import RateLimitException
from utils.ip import is_ipv4, reverse_ipv4
from utils.verdict import Verdict


class SURBLCollector(DNSCollector):
    name = "surbl"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "multi.surbl.org"

    ENDPOINT = "/lookup"

    @staticmethod
    def return_code_to_lists(return_codes: list[str]):
        lists = []

        for rc in return_codes:
            last_digit = int(rc.split(".")[-1])

            if last_digit >= 128:
                last_digit -= 128
                lists.append("cracked site")
            if last_digit >= 64:
                last_digit -= 64
                lists.append("abuse")
            if last_digit >= 32:
                last_digit -= 32
                lists.append("click transfer domain")
            if last_digit >= 16:
                last_digit -= 16
                lists.append("malware site")
            if last_digit >= 8:
                last_digit -= 8
                lists.append("phishing site")
            if last_digit >= 4:
                last_digit -= 4
                lists.append("disposable mail domain")

        return lists

    def collect(self, address: str) -> dict:
        if USE_MOCK_API:
            r = self.session.get(
                self.url(),
                params={"domain": address},
            )

            if not r.ok:
                return {
                    "listed": False,
                    "codes": [],
                    "lists": [],
                }

            return r.json()

        if is_ipv4(address):
            address = reverse_ipv4(address)

        query = f"{address}.{self.BASE_URL}"

        answers = self.resolve_dns(query)

        if "127.0.0.1" in answers:
            raise RateLimitException

        return {
            "listed": bool(answers),
            "codes": answers,
            "lists": self.return_code_to_lists(answers) if bool(answers) else [],
        }

    def classify(self, data: dict) -> Verdict:
        if not data["listed"]:
            return Verdict.BENIGN

        return Verdict.MALICIOUS

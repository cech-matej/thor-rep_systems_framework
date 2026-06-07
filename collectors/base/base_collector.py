from abc import ABC, abstractmethod

from config.settings import USE_MOCK_API, MOCK_API_BASE


class BaseCollector(ABC):
    name = "base"

    supports_domain = False
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = ""  # To be defined in child classes
    ENDPOINT = ""  # To be defined in child classes

    def __init__(self):
        self.session = None  # Will initialize session if needed (like HTTP session or DNS resolver)

    @abstractmethod
    def collect(self, address: str) -> dict:
        """Method to collect data from the source"""
        pass

    @abstractmethod
    def classify(self, data: dict):
        """Method to classify the collected data"""
        pass

    def url(self) -> str:
        """
        Build full URL for the collector.
        Automatically switches to mock API if USE_MOCK_API is True.
        """
        if USE_MOCK_API:
            # construct mock URL automatically based on collector name
            base = f"{MOCK_API_BASE}/{self.name}"
        else:
            base = self.BASE_URL

        return f"{base}{self.ENDPOINT}"

    @staticmethod
    def is_rate_limited(response):
        """
        Default implementation. Most APIs use HTTP 429.
        """

        return response.status_code == 429

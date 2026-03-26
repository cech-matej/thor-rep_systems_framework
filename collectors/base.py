from abc import ABC, abstractmethod
import requests

from config.settings import USE_MOCK_API, MOCK_API_BASE


class BaseCollector(ABC):
    name = "base"

    supports_domain = False
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = ""  # to be defined in child
    ENDPOINT = ""  # to be defined in child

    def __init__(self):
        self.session = requests.Session()

    @abstractmethod
    def collect(self, address: str) -> dict:
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

    def classify(self, data: dict):
        """
        Convert collected data into a Verdict.
        Must be implemented by each collector.
        """
        raise NotImplementedError

import requests
from abc import ABC, abstractmethod
from collectors.base.base_collector import BaseCollector
from utils.exceptions import RateLimitException


class APICollector(BaseCollector, ABC):
    """
    APICollector is a generic collector that interacts with an API to collect data.
    This is an abstract base class for API-based collectors.
    """
    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = True

    def __init__(self):
        super().__init__()
        self.session = requests.Session()  # For handling API calls

    @abstractmethod
    def collect(self, address: str) -> dict:
        """This method should be implemented by subclasses to collect data from a given API."""
        pass

    @abstractmethod
    def classify(self, data: dict):
        """This method should be implemented by subclasses to classify the collected data."""
        pass

    def validate_response(self, response):
        if self.is_rate_limited(response):
            raise RateLimitException

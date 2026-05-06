from abc import ABC, abstractmethod
import dns.resolver
import requests

from collectors.base.base_collector import BaseCollector
from config.settings import USE_MOCK_API


class DNSCollector(BaseCollector, ABC):
    # supports_domain = True
    # supports_ipv4 = True
    # supports_ipv6 = True

    def __init__(self):
        super().__init__()
        self.resolver = dns.resolver.Resolver()  # For DNS resolution
        self.session = requests if USE_MOCK_API else None

    @abstractmethod
    def collect(self, address: str) -> dict:
        """To be implemented by subclasses for collecting DNS data"""
        pass

    @abstractmethod
    def classify(self, data: dict):
        """To be implemented by subclasses for classifying collected data"""
        pass

    def resolve_dns(self, address: str, record_type: str = "A"):
        """
        Resolve DNS records for the given address and record type (A, AAAA, MX, TXT, etc.).

        :param address: The domain or IP address to resolve.
        :param record_type: The type of DNS record to resolve (default is "A").
        :return: A dictionary of resolved records.
        """

        try:
            answers = self.resolver.resolve(address, record_type)
            return [r.to_text() for r in answers]

        except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.Timeout,
                dns.resolver.NoNameservers,
        ):
            return []

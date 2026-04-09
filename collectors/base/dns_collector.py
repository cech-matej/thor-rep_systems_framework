from abc import ABC, abstractmethod
import dns.resolver

from collectors.base.base_collector import BaseCollector


class DNSCollector(BaseCollector, ABC):
    # supports_domain = True
    # supports_ipv4 = True
    # supports_ipv6 = True

    def __init__(self):
        super().__init__()
        self.resolver = dns.resolver.Resolver()  # For DNS resolution

    # def collect(self, address: str) -> dict:
    #     """
    #     Collect A and AAAA DNS records for the given address.
    #     """
    #     dns_data = self.resolve_dns(address)
    #     return dns_data
    #
    # def classify(self, data: dict):
    #     # Example: Classify based on the existence of DNS records
    #     if data['A']:
    #         return "IPv4 found"
    #     elif data['AAAA']:
    #         return "IPv6 found"
    #     else:
    #         return "No IP records found"

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
        dns_records = {record_type: []}

        try:
            # Perform the DNS query based on the record_type parameter
            records = self.resolver.resolve(address, record_type)
            dns_records[record_type] = [rdata.to_text() for rdata in records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            dns_records[record_type] = []  # Empty list if no records are found

        return dns_records
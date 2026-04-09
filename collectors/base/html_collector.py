from abc import ABC, abstractmethod
import requests
from bs4 import BeautifulSoup

from collectors.base.base_collector import BaseCollector


class HTMLCollector(BaseCollector, ABC):
    """
    HTMLCollector is an abstract base class for collectors that scrape HTML content from a webpage.
    Subclasses must implement the `collect()` and `classify()` methods.
    """
    # supports_domain = True
    # supports_ipv4 = False
    # supports_ipv6 = False

    def __init__(self):
        super().__init__()

    @abstractmethod
    def collect(self, address: str) -> dict:
        """
        Abstract method to collect data from the given HTML page.
        Subclasses must implement this method to scrape HTML content.
        """
        pass

    @abstractmethod
    def classify(self, data: dict):
        """
        Abstract method to classify the collected data (e.g., identifying if the site is "malicious").
        Subclasses must implement this method.
        """
        pass

    @staticmethod
    def scrape_html(address: str) -> BeautifulSoup:
        """
        Helper method to scrape and return a BeautifulSoup object of the HTML page.
        This allows further traversal and data extraction using BeautifulSoup.

        :param address: The URL to scrape.
        :return: BeautifulSoup object to traverse and parse the HTML content.
        """
        try:
            response = requests.get(address)
            response.raise_for_status()  # Raise an exception for bad responses
            soup = BeautifulSoup(response.text, 'html.parser')  # Parse HTML and return the BeautifulSoup object
            return soup
        except requests.exceptions.RequestException as e:
            print(f"Error scraping HTML: {e}")
            return None  # Return None on failure
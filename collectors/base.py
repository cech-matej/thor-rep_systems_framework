from abc import ABC, abstractmethod
import requests
from typing import List, Callable

from config.settings import USE_MOCK_API, MOCK_API_BASE


class BaseCollector(ABC):
    name = "base"

    supports_domain = False
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = ""  # to be defined in child
    ENDPOINT = ""  # to be defined in child

    # # Visualization defaults
    # vis_labels: List[str] = []
    # vis_colors: List[str] = []
    # vis_classify: Callable = None  # function(data) -> List[int]

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

    # # Visualization helper
    # def classify_data(self, data: list) -> List[int]:
    #     if self.vis_classify:
    #         return self.vis_classify(data)
    #     raise NotImplementedError("Collector has no classification function defined")

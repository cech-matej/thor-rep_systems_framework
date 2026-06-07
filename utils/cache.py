import json
from pathlib import Path


class CollectorCache:
    def __init__(self, collector_name):
        self.path = Path("cache") / f"{collector_name}.json"

    def load(self):
        if not self.path.exists():
            return {
                "completed": False,
                "rate_limited": False,
                "ipv4": {},
                "ipv6": {},
                "domains": {},
            }

        with open(self.path) as f:
            return json.load(f)

    def save(self, data):
        self.path.parent.mkdir(exist_ok=True)

        with open(self.path, "w") as f:
            json.dump(data, f, indent=4)

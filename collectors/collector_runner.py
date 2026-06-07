from utils.cache import CollectorCache
from config.settings import (
    ENABLE_CACHE,
    RESUME_COLLECTION,
    SAVE_PROGRESS
)
from utils.exceptions import RateLimitException


class CollectorRunner:
    def __init__(self, collector):
        self.collector = collector

        if ENABLE_CACHE:
            self.cache = CollectorCache(collector.name)
            self.state = self.cache.load()

        else:
            self.cache = None
            self.state = {
                "completed": False,
                "rate_limited": False,
                "ipv4": {},
                "ipv6": {},
                "domains": {},
            }

    def save(self):
        if ENABLE_CACHE and SAVE_PROGRESS:
            self.cache.save(self.state)

    def collect_entity(self, entity_type, entity):
        bucket = self.state[entity_type]

        if RESUME_COLLECTION and entity in bucket:
            return

        try:
            result = self.collector.collect(entity)

            bucket[entity] = {
                "status": "success",
                "data": result,
            }

            self.save()

        except RateLimitException:
            self.state["rate_limited"] = True
            self.save()

            raise

    def run(self, domains, ipv4_set, ipv6_set):
        self.state["rate_limited"] = False

        try:
            if self.collector.supports_ipv4:
                for ip in ipv4_set:
                    self.collect_entity("ipv4", ip)

            if self.collector.supports_ipv6:
                for ip in ipv6_set:
                    self.collect_entity("ipv6", ip)

            if self.collector.supports_domain:
                for domain in domains:
                    self.collect_entity("domains", domain["domain_name"])

        except RateLimitException:
            print(f"{self.collector.name}: rate limit reached")

            return False

        self.state["completed"] = True
        self.save()

        return True

    def build_output(self, domains):
        enriched_domains = []

        for domain in domains:
            entry = dict(domain)
            dn = domain["domain_name"]

            if self.collector.supports_domain:
                cached = self.state["domains"].get(dn)
                entry["dn_data"] = cached["data"] if cached else None

            if self.collector.supports_ipv4:
                for ip in domain.get("A", []):
                    cached = self.state["ipv4"].get(ip)
                    entry[ip] = cached["data"] if cached else None

            if self.collector.supports_ipv6:
                for ip in domain.get("AAAA", []):
                    cached = self.state["ipv6"].get(ip)
                    entry[ip] = cached["data"] if cached else None

            enriched_domains.append(entry)

        return enriched_domains

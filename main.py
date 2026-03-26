import threading
import time
import json

from collectors.abuseipdb import AbuseIPDBCollector
from collectors.cloudflare_radar import CloudflareRadarCollector
from collectors.criminalip import CriminalIPCollector
from collectors.fortiguard import FortiGuardCollector
from collectors.google_safe_browsing import GoogleSafeBrowsingCollector
from collectors.greynoise import GreyNoiseCollector
from collectors.hybrid_analysis import HybridAnalysisCollector
from collectors.nerd import NerdCollector
from collectors.pulsedive import PulsediveCollector
from collectors.threatfox import ThreatFoxCollector
from collectors.virustotal import VirusTotalCollector
from collectors.visualization.visualize import visualize
from mock_api.run import run_mock_api
from config.settings import MOCK_API_HOST, MOCK_API_PORT, USE_MOCK_API

from utils.input import load_domains
from utils.output import create_output_dir


def start_mock_api():
    thread = threading.Thread(
        target=run_mock_api,
        kwargs={
            "host": MOCK_API_HOST,
            "port": MOCK_API_PORT
        },
        daemon=True  # shuts down when main program exits
    )

    thread.start()


def extract_unique_ips(domains):
    ipv4_set = set()
    ipv6_set = set()

    for domain in domains:
        ipv4_set.update(domain.get("A", []))
        ipv6_set.update(domain.get("AAAA", []))

    return ipv4_set, ipv6_set


if __name__ == "__main__":
    if USE_MOCK_API:
        start_mock_api()
        time.sleep(.5)

    collectors = [
        AbuseIPDBCollector(),
        CloudflareRadarCollector(),
        CriminalIPCollector(),
        FortiGuardCollector(),
        GoogleSafeBrowsingCollector(),
        GreyNoiseCollector(),
        HybridAnalysisCollector(),
        NerdCollector(),
        PulsediveCollector(),
        ThreatFoxCollector(),
        VirusTotalCollector()
    ]

    domains = load_domains("test_domains.json")
    output_dir = create_output_dir(USE_MOCK_API)

    ipv4_set, ipv6_set = extract_unique_ips(domains)

    for collector in collectors:
        print(f"Running collector: {collector.name}")

        ip_results = {}
        dn_results = {}

        # collect IPv4
        if collector.supports_ipv4:
            for ip in ipv4_set:
                ip_results[ip] = collector.collect(ip)

        # collect IPv6
        if collector.supports_ipv6:
            for ip in ipv6_set:
                ip_results[ip] = collector.collect(ip)

        # collect domain names
        if collector.supports_domain:
            for domain in domains:
                dn = domain["domain_name"]
                dn_results[dn] = collector.collect(dn)

        enriched_domains = []

        for domain in domains:
            entry = dict(domain)

            dn = domain["domain_name"]

            if collector.supports_domain:
                entry["dn_data"] = dn_results.get(dn)

            if collector.supports_ipv4:
                for ip in domain.get("A", []):
                    entry[ip] = ip_results.get(ip)

            if collector.supports_ipv6:
                for ip in domain.get("AAAA", []):
                    entry[ip] = ip_results.get(ip)

            enriched_domains.append(entry)

        output_file = output_dir / f"{collector.name}.json"

        with open(output_file, "w") as f:
            json.dump(enriched_domains, f, indent=2)

        print(f"Saved: {output_file}")

    visualize(output_dir, show_values=True)
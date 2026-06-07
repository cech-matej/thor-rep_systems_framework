import threading
import time
import json

from collectors.api.abuseipdb import AbuseIPDBCollector
from collectors.api.cloudflare_radar import CloudflareRadarCollector
from collectors.api.criminalip import CriminalIPCollector
from collectors.api.fortiguard import FortiGuardCollector
from collectors.api.google_safe_browsing import GoogleSafeBrowsingCollector
from collectors.api.greynoise import GreyNoiseCollector
from collectors.api.hybrid_analysis import HybridAnalysisCollector
from collectors.api.nerd import NerdCollector
from collectors.api.opentip_kaspersky import OpentipKasperskyCollector
from collectors.api.otx_alienvault import OTXAlienvaultCollector
from collectors.api.pulsedive import PulsediveCollector
from collectors.api.threatfox import ThreatFoxCollector
from collectors.api.virustotal import VirusTotalCollector
from collectors.api.whoisxmlapi_domain_reputation import WhoisXMLAPIDomainReputationCollector
from collectors.collector_runner import CollectorRunner

from collectors.dns.spamhaus_dbl import SpamhausDBLCollector
from collectors.dns.spamhaus_zen import SpamhausZenCollector

from collectors.html.project_honeypot import ProjectHoneypotCollector
from collectors.html.urlvoid import URLVoid

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
        OpentipKasperskyCollector(),
        OTXAlienvaultCollector(),
        PulsediveCollector(),
        ThreatFoxCollector(),
        VirusTotalCollector(),
        WhoisXMLAPIDomainReputationCollector(),

        SpamhausDBLCollector(),
        SpamhausZenCollector(),

        ProjectHoneypotCollector(),
        URLVoid(),
    ]

    domains = load_domains("test_domains.json")
    output_dir = create_output_dir(USE_MOCK_API)

    ipv4_set, ipv6_set = extract_unique_ips(domains)

    for collector in collectors:
        print(f"Running collector: {collector.name}")

        runner = CollectorRunner(collector)
        runner.run(domains, ipv4_set, ipv6_set)

        output = runner.build_output(domains)

        output_file = output_dir / f"{collector.name}.json"

        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)

        print(f"Saved: {output_file}")

    visualize(output_dir, show_values=True)

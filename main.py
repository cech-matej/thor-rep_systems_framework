import concurrent.futures
import datetime
from pathlib import Path
import threading
import time
import json

from collectors.api.abuseipdb import AbuseIPDBCollector
from collectors.api.cloudflare_radar import CloudflareRadarCollector
from collectors.api.criminalip import CriminalIPCollector
from collectors.api.fortiguard import FortiGuardCollector
from collectors.api.google_safe_browsing import GoogleSafeBrowsingCollector
from collectors.api.greynoise import GreyNoiseCollector
from collectors.api.griffinguard import GriffinGuardCollector
from collectors.api.hybrid_analysis import HybridAnalysisCollector
from collectors.api.nerd import NerdCollector
from collectors.api.opentip_kaspersky import OpentipKasperskyCollector
from collectors.api.otx_alienvault import OTXAlienvaultCollector
from collectors.api.phishing_initiative import PhishingInitiativeCollector
from collectors.api.pulsedive import PulsediveCollector
from collectors.api.threatfox import ThreatFoxCollector
from collectors.api.virustotal import VirusTotalCollector
from collectors.api.whoisxmlapi_domain_reputation import WhoisXMLAPIDomainReputationCollector
from collectors.collector_runner import CollectorRunner

from collectors.dns.spamhaus_dbl import SpamhausDBLCollector
from collectors.dns.spamhaus_zen import SpamhausZenCollector
from collectors.dns.surbl import SURBLCollector

from collectors.html.project_honeypot import ProjectHoneypotCollector
from collectors.html.urlvoid import URLVoid

from collectors.visualization.visualize import visualize
from mock_api.run import run_mock_api
from config.settings import MOCK_API_HOST, MOCK_API_PORT, USE_MOCK_API, MAX_WORKERS

from utils.input import load_domains
from utils.output import create_output_dir
from utils.webhook import post_to_webhook


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


# def extract_unique_ips(domains):
#     ipv4_set = set()
#     ipv6_set = set()
#
#     for domain in domains:
#         ipv4_set.update(domain.get("A", []))
#         ipv6_set.update(domain.get("AAAA", []))
#
#     return ipv4_set, ipv6_set

def extract_unique_ips(domains):
    ipv4 = []
    ipv6 = []
    seen_ipv4 = set()
    seen_ipv6 = set()

    for domain in domains:
        for ip in domain.get("A", []):
            if ip not in seen_ipv4:
                seen_ipv4.add(ip)
                ipv4.append(ip)

        for ip in domain.get("AAAA", []):
            if ip not in seen_ipv6:
                seen_ipv6.add(ip)
                ipv6.append(ip)

    return ipv4, ipv6


def run_collector(collector, domains, ipv4_set, ipv6_set, output_dir):
    """
    Worker function executed by each thread.
    """

    print(f"Running collector: {collector.name} | {datetime.datetime.now()}")
    
    runner = CollectorRunner(collector)
    curr_status, collected_now, completed, collected_all_time = runner.run(domains, ipv4_set, ipv6_set)

    output = runner.build_output(domains)
    output_file = output_dir / f"{collector.name}.json"

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Saved: {output_file}")

    return {
        "name": collector.name,
        "curr_status": curr_status,
        "collected_now": collected_now,
        "completed": completed,
        "collected_all_time": collected_all_time
    }


if __name__ == "__main__":
    if USE_MOCK_API:
        start_mock_api()
        time.sleep(.5)

    collectors = [
        # AbuseIPDBCollector(),
        CloudflareRadarCollector(),
        # CriminalIPCollector(),
        # FortiGuardCollector(),
        GoogleSafeBrowsingCollector(),
        # GreyNoiseCollector(),
        # GriffinGuardCollector(),
        # HybridAnalysisCollector(),
        # NerdCollector(),
        OpentipKasperskyCollector(),
        # OTXAlienvaultCollector(),
        PhishingInitiativeCollector(),
        # PulsediveCollector(),
        ThreatFoxCollector(),
        VirusTotalCollector(),
        # WhoisXMLAPIDomainReputationCollector(),
        #
        SpamhausDBLCollector(),
        # SpamhausZenCollector(),
        SURBLCollector(),
        #
        # ProjectHoneypotCollector(),
        URLVoid(),
    ]

    domains = load_domains("test_domains.json")
    output_dir = create_output_dir(USE_MOCK_API)

    ipv4_set, ipv6_set = extract_unique_ips(domains)

    webhook_curr_services = []
    webhook_all_time_services = []

    print(f"Starting parallel execution with {MAX_WORKERS} worker(s)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all collectors to the thread pool
        futures = { executor.submit(run_collector, c, domains, ipv4_set, ipv6_set, output_dir): c for c in collectors }

        # Collect results as they complete (thread-safe aggregation)
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                webhook_curr_services.append((result["name"], result["curr_status"], result["collected_now"]))
                webhook_all_time_services.append((result["name"], result["completed"], result["collected_all_time"]))

            except Exception as e:
                collector_name = futures[future].name
                print(f"Error running {collector_name}: {e}")

    post_to_webhook(webhook_curr_services, webhook_all_time_services)

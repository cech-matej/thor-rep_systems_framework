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


def get_all_collectors():
    return [
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
        VirusTotalCollector(),
    ]


def get_collector_map():
    """
    Returns:
        {
            "abuseipdb": AbuseIPDBCollector(),
            ...
        }
    """
    return {collector.name: collector for collector in get_all_collectors()}
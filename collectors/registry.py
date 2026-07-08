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
from collectors.dns.spamhaus_dbl import SpamhausDBLCollector
from collectors.dns.spamhaus_zen import SpamhausZenCollector

from collectors.html.project_honeypot import ProjectHoneypotCollector
from collectors.html.urlvoid import URLVoid


def get_all_collectors():
    return [
        # API collectors
        AbuseIPDBCollector(),
        CloudflareRadarCollector(),
        CriminalIPCollector(),
        FortiGuardCollector(),
        GoogleSafeBrowsingCollector(),
        GreyNoiseCollector(),
        GriffinGuardCollector(),
        HybridAnalysisCollector(),
        NerdCollector(),
        OpentipKasperskyCollector(),
        OTXAlienvaultCollector(),
        PhishingInitiativeCollector(),
        PulsediveCollector(),
        ThreatFoxCollector(),
        VirusTotalCollector(),
        WhoisXMLAPIDomainReputationCollector(),

        # DNS collectors
        SpamhausDBLCollector(),
        SpamhausZenCollector(),

        # HTML collectors
        ProjectHoneypotCollector(),
        URLVoid()
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
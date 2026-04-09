"""
Registers routes for the mock API
"""

__author__ = "Matěj Čech"

from flask import Flask
from .abuseipdb import abuseipdb_routes
from .cloudflare_radar import cloudflare_radar_routes
from .criminalip import criminalip_routes
from .fortiguard import fortiguard_routes
from .google_safe_browsing import gsb_routes
from .greynoise import greynoise_routes
from .hybrid_analysis import hybrid_analysis_routes
from .nerd import nerd_routes
from .opentip_kaspersky import opentip_kaspersky_routes
from .otx_alienvault import otx_alienvault_routes
from .project_honeypot import project_honeypot_routes
from .pulsedive import pulsedive_routes
from .threatfox import threatfox_routes
from .urlvoid import urlvoid_routes
from .virustotal import virustotal_routes
from .whoisxmlapi_domain_reputation import whoisxml_domain_reputation_routes

def create_app():
    app = Flask(__name__)

    # Register the blueprints with the app
    app.register_blueprint(abuseipdb_routes)
    app.register_blueprint(cloudflare_radar_routes)
    app.register_blueprint(criminalip_routes)
    app.register_blueprint(fortiguard_routes)
    app.register_blueprint(gsb_routes)
    app.register_blueprint(greynoise_routes)
    app.register_blueprint(hybrid_analysis_routes)
    app.register_blueprint(nerd_routes)
    app.register_blueprint(opentip_kaspersky_routes)
    app.register_blueprint(otx_alienvault_routes)
    app.register_blueprint(project_honeypot_routes)
    app.register_blueprint(pulsedive_routes)
    app.register_blueprint(threatfox_routes)
    app.register_blueprint(urlvoid_routes)
    app.register_blueprint(virustotal_routes)
    app.register_blueprint(whoisxml_domain_reputation_routes)

    return app

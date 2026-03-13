"""
Google Safe Browsing route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

from .validate import validate_dn, validate_ipv4

gsb_routes = Blueprint('gsb', __name__, url_prefix='/google_safe_browsing')

@gsb_routes.route('/v4/threatMatches:find', methods=['POST'])
def report():
    data = request.get_json()

    err = jsonify({"error": "Provide an address"}), 400

    if not data or 'threatInfo' not in data:
        return err

    threat_info = data['threatInfo']
    if not 'threatEntries' in threat_info:
        return err

    threat_entries = threat_info['threatEntries']
    if len(threat_entries) < 1:
        return err

    entry = threat_entries[0]
    if not 'url' in entry:
        return err

    url = entry['url']

    if not validate_ipv4(url) and not validate_dn(url):
        return jsonify({"error": "Provide valid address"}), 400

    possible_threat_type = ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"]

    return jsonify({
        "matches": [
            {
                "threatType": random.choice(possible_threat_type),
            }
        ]
    })

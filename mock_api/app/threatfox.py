"""
Threatfox route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

threatfox_routes = Blueprint('threatfox', __name__, url_prefix='/threatfox')

@threatfox_routes.route('/api/v1', methods=['POST'])
def report():
    data = request.get_json()

    if not data or 'search_term' not in data:
        return jsonify({"error": "Provide an address"}), 400

    return jsonify({
        "query_status": "ok",
        "data": [
            {
                "threat_type": "botnet_cc",
                "malware": "win.cobalt_strike",
                "confidence_level": random.randint(0, 100),
                "tags": [
                    "CobaltStrike",
                    "drb-ra"
                ]
            }
        ]
    })

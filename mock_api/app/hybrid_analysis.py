"""
Hybrid Analysis route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

hybrid_analysis_routes = Blueprint('hybrid_analysis', __name__, url_prefix='/hybrid_analysis')

@hybrid_analysis_routes.route('/api/v2/search/terms', methods=['POST'])
def report():
    host = request.form.get("host")
    domain = request.form.get("domain")

    if not host and not domain:
        return jsonify({"error": "Provide an address"}), 400

    possible_verdict = ["malicious", "suspicious", "whitelisted", "no specific threat"]

    return jsonify({
        "result": [
            {
                "verdict": random.choice(possible_verdict),
                "threat_score": random.randint(0, 100),
            }
            for _ in range(random.randint(1, 5))
        ]
    })

import ipaddress
from flask import Blueprint, jsonify, request
import random

pulsedive_routes = Blueprint('pulsedive', __name__, url_prefix='/pulsedive')

@pulsedive_routes.route('/api/info.php', methods=['GET'])
def ip_report():
    addr = request.args.get('indicator')

    if not addr:
        return jsonify({"error": "Please provide an address address"}), 400

    possible_risk = ['none', 'low', 'medium', 'high', 'critical', 'retired', 'unknown']
    possible_manualrisk = [0, 1]

    return jsonify({
        "score": {
            "risk": random.choice(possible_risk),
            "risk_recommended": random.choice(possible_risk),
            "manualrecommended": random.choice(possible_manualrisk),
        }
    })
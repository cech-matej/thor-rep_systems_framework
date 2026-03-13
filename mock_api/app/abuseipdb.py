"""
AbuseIPDB route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

from .validate import validate_ip

abuseipdb_routes = Blueprint('abuseipdb', __name__, url_prefix='/abuseipdb')

@abuseipdb_routes.route('/api/v2/check', methods=['GET'])
def ip_report():
    ip = request.args.get('ipAddress')

    if not ip:
        return jsonify({"error": "Provide an IP address"}), 400

    # Validate IP
    if not validate_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400

    possible_bool = [True, False, None]

    return jsonify({
        "data": {
            "isWhitelisted": random.choice(possible_bool),
            "abuseConfidenceScore": random.randint(0, 100),
            "isTor": random.choice(possible_bool),
            "totalReports": random.randint(0, 1000),
        }
    })

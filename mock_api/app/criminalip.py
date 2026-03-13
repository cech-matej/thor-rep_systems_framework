import ipaddress
from flask import Blueprint, jsonify, request
import random

criminalip_routes = Blueprint('criminalip', __name__, url_prefix='/criminalip')

@criminalip_routes.route('/v1/asset/ip/report', methods=['GET'])
def ip_report():
    ip = request.args.get('ip')

    if not ip:
        return jsonify({"error": "Please provide an IPv4 address"}), 400

    # Validate IPv4
    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return jsonify({'error': 'Invalid IPv4 address'}), 400

    possible_score = ['Safe', 'Low', 'Moderate', 'Dangerous', 'Critical']

    return jsonify({
        "score": {
            "inbound": random.choice(possible_score),
            "outbound": random.choice(possible_score),
        }
    })
import ipaddress
from flask import Blueprint, jsonify, request
import random
import re

virustotal_routes = Blueprint('virustotal', __name__, url_prefix='/virustotal')

def generate_report():
    total = 94

    # Generate 3 random cut points between 0 and total
    cuts = sorted(random.sample(range(total + 1), 3))
    malicious = cuts[0]
    suspicious = cuts[1] - cuts[0]
    undetected = cuts[2] - cuts[1]
    harmless = total - cuts[2]

    return jsonify({
        "data": {
            "attributes": {
                "reputation": random.randint(-10, 10),
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                }
            }
        }
    })

@virustotal_routes.route('/api/v3/ip_address/<ip>', methods=['GET'])
def ip_report(ip):
    try:
        # Try to parse the IP address, this will validate if it's either IPv4 or IPv6
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400  # 400 Bad Request for invalid IP

    return generate_report()

@virustotal_routes.route('/api/v3/domains/<dn>', methods=['GET'])
def dn_report(dn):
    # Simple regex for validating domain names
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if not re.match(domain_regex, dn):
        return jsonify({"error": "Invalid domain name"}), 400

    return generate_report()
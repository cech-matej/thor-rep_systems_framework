"""
Opentip Kaspersky route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

from .validate import validate_ipv4, validate_dn

opentip_kaspersky_routes = Blueprint('opentip_kaspersky', __name__, url_prefix='/opentip_kaspersky')

def generate_report(info_element):
    possible_zone = ["Green", "Grey", "Yellow", "Orange", "Red"]
    possible_category = ["CATEGORY_MALWARE", "CATEGORY_ADWARE", "CATEGORY_PHISHING", "CATEGORY_COMPROMISED",
                         "CATEGORY_BOTNET_CNC"]

    return jsonify({
        "Zone": random.choice(possible_zone),
        info_element : {
            "CategoriesWithZone": [
                {
                    "Name": random.choice(possible_category),
                    "Zone": random.choice(possible_zone)
                }
            ]
        }
    })

@opentip_kaspersky_routes.route('/api/v1/search/ip', methods=['GET'])
def report_ip():
    ip = request.args.get('request')

    if not ip:
        return jsonify({"error": "Provide an IPv4 address"}), 400

    # Validate IPv4
    if not validate_ipv4(ip):
        return jsonify({'error': 'Invalid IP address'}), 400

    return generate_report("IpGeneralInfo")


@opentip_kaspersky_routes.route('/api/v1/search/domain', methods=['GET'])
def report_dn():
    dn = request.args.get('request')

    if not dn:
        return jsonify({"error": "Provide an domain name"}), 400

    # Validate DN
    if not validate_dn(dn):
        return jsonify({'error': 'Invalid domain name'}), 400

    return generate_report("DomainGeneralInfo")

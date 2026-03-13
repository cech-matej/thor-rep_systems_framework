import ipaddress
from flask import Blueprint, jsonify, request
import random

greynoise_routes = Blueprint('greynoise', __name__, url_prefix='/greynoise')

@greynoise_routes.route('/v3/community/<ip>', methods=['GET'])
def ip_report(ip):
    # Validate IPv4
    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return jsonify({'error': 'Invalid IPv4 address'}), 400

    possible_bool = [True, False]
    possible_classification = ['benign', 'unknown', 'malicious']

    return jsonify({
        "noise": random.choice(possible_bool),
        "riot": random.choice(possible_bool),
        "classification": random.choice(possible_classification)
    })
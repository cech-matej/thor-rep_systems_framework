"""
Cloudflare Radar route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

from .validate import validate_ipv4, validate_dn

cloudflare_radar_routes = Blueprint('cloudflare_radar', __name__, url_prefix='/cloudflare_radar')

# @cloudflare_radar_routes.route('/client/v4/accounts/<account_id>/urlscanner/v2/search', methods=['GET'])
# def report(account_id):
#     ip = request.args.get('page.ip')
#     dn = request.args.get('page.domain')
#
#     if not ip and not dn:
#         return jsonify({"error": "Provide an address"}), 400
#
#     if ip:
#         # Validate IPv4
#         if not validate_ipv4(ip):
#             return jsonify({'error': 'Invalid IP address'}), 400
#
#     if dn:
#         if not validate_dn(dn):
#             return jsonify({'error': 'Invalid domain name'}), 400
#
#     possible_malicious = [True, False]
#
#     return jsonify({
#         "results": [
#             {
#                 "verdicts": random.choice(possible_malicious),
#             }
#         ]
#     })


@cloudflare_radar_routes.route(
    "/client/v4/accounts/<account_id>/urlscanner/v2/search", methods=["GET"]
)
def report(account_id):
    q = request.args.get("q", "")
    ip = None
    dn = None

    if q.startswith("page.ip:"):
        ip = q.split("page.ip:")[1]
    elif q.startswith("page.domain:"):
        dn = q.split("page.domain:")[1]

    if not ip and not dn:
        return jsonify({"error": "Provide an address"}), 400

    if ip:
        # Validate IPv4
        if not validate_ipv4(ip):
            return jsonify({"error": "Invalid IP address"}), 400

    if dn:
        if not validate_dn(dn):
            return jsonify({"error": "Invalid domain name"}), 400

    possible_malicious = [True, False]

    return jsonify({
        "results": [
            {
                "verdicts": {"malicious": random.choice(possible_malicious)},
            }
        ]
    })

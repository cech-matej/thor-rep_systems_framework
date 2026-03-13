"""
NERD route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify
import random

from .validate import validate_ipv4

nerd_routes = Blueprint('nerd', __name__, url_prefix='/nerd')

@nerd_routes.route('/nerd/api/v1/ip/<ip>', methods=['GET'])
def ip_report(ip):
    if not validate_ipv4(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    return jsonify({
        "rep": round(random.random(), 2)
    })

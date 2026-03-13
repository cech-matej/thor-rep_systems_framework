"""
Fortiguard route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request
import random

fortiguard_routes = Blueprint('fortiguard', __name__, url_prefix='/fortiguard')

@fortiguard_routes.route('/learnmore/check-blocklist', methods=['POST'])
def report():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({"error": "Provide an address"}), 400

    possible_spam = [True, False]

    return jsonify({
        "spam": random.choice(possible_spam),
    })

from flask import Blueprint, jsonify, request
import random

from .validate import validate_ip

spamhaus_zen_routes = Blueprint("spamhaus_zen", __name__, url_prefix="/spamhaus_zen")

CODES = [
    "127.0.0.2",
    "127.0.0.3",
    "127.0.0.4",
    "127.0.0.9",
    "127.0.0.10",
    "127.0.0.11",
]

MAP = {
    "127.0.0.2": "SBL - Spamhaus SBL data",
    "127.0.0.3": "SBL - Spamhaus CSS data",
    "127.0.0.4": "XBL - Spamhaus CBL data",
    "127.0.0.9": "PBL - Spamhaus DROP data",
    "127.0.0.10": "PBL - ISP maintained",
    "127.0.0.11": "PBL - Spamhaus maintained",
}


@spamhaus_zen_routes.route("/lookup", methods=["GET"])
def lookup():
    ip = request.args.get("ip")

    if not ip:
        return jsonify({"error": "Provide IP"}), 400

    if not validate_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400

    listed = random.choice([True, False])

    codes = [random.choice(CODES)] if listed else []

    return jsonify({
        "listed": listed,
        "codes": codes,
        "lists": [MAP[c] for c in codes],
    })
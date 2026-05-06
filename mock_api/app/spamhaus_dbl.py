from flask import Blueprint, jsonify, request
import random

spamhaus_dbl_routes = Blueprint("spamhaus_dbl", __name__, url_prefix="/spamhaus_dbl")

CODES = [
    "127.0.1.2",
    "127.0.1.4",
    "127.0.1.5",
    "127.0.1.6",
    "127.0.1.102",
    "127.0.1.103",
    "127.0.1.104",
    "127.0.1.105",
    "127.0.1.106",
]

MAP = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C2",
    "127.0.1.102": "abused legit spam",
    "127.0.1.103": "abused spammed redirector domain",
    "127.0.1.104": "abused legit phish",
    "127.0.1.105": "abused legit malware",
    "127.0.1.106": "abused legit botnet C2",
}


@spamhaus_dbl_routes.route("/lookup", methods=["GET"])
def lookup():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Provide domain"}), 400

    listed = random.choice([True, False])

    codes = [random.choice(CODES)] if listed else []

    return jsonify({
        "listed": listed,
        "codes": codes,
        "lists": [MAP[c] for c in codes],
    })

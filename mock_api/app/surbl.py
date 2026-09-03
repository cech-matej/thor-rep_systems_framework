from flask import Blueprint, jsonify, request
import random

surbl_routes = Blueprint("surbl", __name__, url_prefix="/surbl")

CODES = [4, 8, 16, 32, 64, 128]

MAP = {
    "4": "disposable mail domain",
    "8": "phishing site",
    "16": "malware site",
    "32": "click transfer domain",
    "64": "abuse",
    "128": "cracked site",
}


@surbl_routes.route("/lookup", methods=["GET"])
def lookup():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Provide domain or ipv4"}), 400

    listed = random.choice([True, False])

    k = random.randint(1, min(3, len(CODES)))

    chosen = random.sample(CODES, k)
    total = sum(chosen)

    return jsonify({
        "listed": listed,
        "codes": f"127.0.0.{total}" if listed else "",
        "lists": [MAP[f"{c}"] for c in chosen] if listed else ""
    })

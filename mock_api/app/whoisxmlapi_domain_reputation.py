from flask import Blueprint, jsonify
import random

whoisxml_domain_reputation_routes = Blueprint('whoisxmlapi_domain_reputation',
                                              __name__, url_prefix='/whoisxmlapi_domain_reputation')

@whoisxml_domain_reputation_routes.route('/api/v2', methods=['GET'])
def report():
    return jsonify({
        "reputationScore": round(random.uniform(0, 100), 2)
    })

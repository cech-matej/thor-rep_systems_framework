from flask import Blueprint, jsonify
import random

otx_alienvault_routes = Blueprint('otx_alienvatul', __name__, url_prefix='/otx_alienvault')

@otx_alienvault_routes.route('/api/v1/indicators/IPv4/<address>/general', methods=['GET'])
@otx_alienvault_routes.route('/api/v1/indicators/IPv6/<address>/general', methods=['GET'])
@otx_alienvault_routes.route('/api/v1/indicators/domain/<address>/general', methods=['GET'])
def report(address):
    return jsonify({
        "indicator": address,
        "pulse_info": {
            "count": random.randint(0, 5),
        },
    })
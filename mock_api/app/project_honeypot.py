"""
ProjectHoneypot route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request, render_template_string
import random

from .validate import validate_ipv4

project_honeypot_routes = Blueprint('project_honeypot', __name__, url_prefix='/project_honeypot')

@project_honeypot_routes.route('/ip_<ip>', methods=['GET'])
def ip_report(ip):
    if not validate_ipv4(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    # Simulate random decision (either return simple h2 or h2 with child element)
    return_html = random.choice([True, False])  # True = h2 with child element, False = just h2

    if return_html:
        # Return <h2> with a child element (e.g., a <p>)
        html_content = """
        <html>
            <body>
                <h2>Report for IP: {{ ip }} <a href="/">When a child element is present, the IP is malicious.</a></h2>
            </body>
        </html>
        """
    else:
        # Return just the <h2>
        html_content = """
        <html>
            <body>
                <h2>Report for IP: {{ ip }}</h2>
            </body>
        </html>
        """

    # Render the HTML content with the dynamic IP address
    return render_template_string(html_content, ip=ip)

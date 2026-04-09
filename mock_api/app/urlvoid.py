"""
URLVoid route logic
"""

__author__ = "Matěj Čech"

from flask import Blueprint, jsonify, request, render_template_string
import random

urlvoid_routes = Blueprint('urlvoid', __name__, url_prefix='/urlvoid')

@urlvoid_routes.route('/scan/<dn>', methods=['GET'])
def dn_report(dn):
    detection_counts = random.randint(0, 35)

    html_content = """
    <html>
        <div class="panel-body">
      
                <div class="table-responsive">
                <table class="table table-custom table-striped">
                <tbody>
                <tr><td width="260"><span class="font-bold">Website Address</span></td><td><strong>{{ dn }}</strong></td></tr>
                <tr><td><span class="font-bold">Last Analysis</span></td><td>32 minutes ago &nbsp;|&nbsp; <i class="fa fa-refresh" aria-hidden="true"></i> <a href="https://www.urlvoid.com/update/{{ dn }}/" rel="nofollow">Rescan</a></td></tr>
                <tr><td><span class="font-bold">Detections Counts</span></td><td><span class="label label-success">{{ detection_counts }}/35</span></td></tr>
                
                                                <tr><td><span class="font-bold">Domain Registration</span></td><td>1997-09-15 | 29 years ago</td></tr>
                                                
                <tr><td><span class="font-bold">Domain Information</span></td><td><i class="fa fa-user-secret" aria-hidden="true"></i> <a href="https://www.urlvoid.com/whois-lookup/" target="_blank">WHOIS Lookup</a> | <a href="https://www.urlvoid.com/dns-records-lookup/" target="_blank">DNS Records</a> | <a href="https://www.urlvoid.com/ping-host-ip-online/" target="_blank">Ping</a></td></tr>
                <tr><td><span class="font-bold">IP Address</span></td><td><strong>172.253.122.100</strong> &nbsp; <a href="https://www.urlvoid.com/ip/172.253.122.100/" target="_blank" rel="nofollow">Find Websites</a> &nbsp;|&nbsp; <a href="http://www.ipvoid.com/" target="_blank">IPVoid</a> &nbsp;|&nbsp; <a href="https://www.urlvoid.com/whois-lookup/" target="_blank">Whois</a></td></tr>
                <tr><td><span class="font-bold">Reverse DNS</span></td><td>bh-in-f100.1e100.net</td></tr>
                <tr><td><span class="font-bold">ASN</span></td><td><a href="http://bgp.he.net/AS15169" target="_blank" rel="nofollow" title="Open http://bgp.he.net">AS15169</a> Google LLC</td></tr>
                <tr><td><span class="font-bold">Server Location</span></td><td><img src="https://www.urlvoid.com/images/flags/us.gif" alt="" /> (US) United States</td></tr>
                <tr><td><span class="font-bold">Latitude\Longitude</span></td><td>37.751 / -97.822 &nbsp; <i class="fa fa-map-marker" aria-hidden="true"></i> <a href="https://maps.google.com/?q=37.751,-97.822" target="_blank" rel="nofollow">Google Map</a></td></tr>
                <tr><td><span class="font-bold">City</span></td><td>Unknown</td></tr>
                <tr><td><span class="font-bold">Region</span></td><td>Unknown</td></tr>
                </tbody>
                </table>
                </div>
      </div>
    </html>
    """

    # Render the HTML content with the dynamic IP address
    return render_template_string(html_content, dn=dn, detection_counts=detection_counts)

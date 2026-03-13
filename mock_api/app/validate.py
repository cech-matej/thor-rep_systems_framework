"""
Address validators
"""

__author__ = "Matěj Čech"

import ipaddress
import re

def validate_ipv4(ip: str) -> bool:
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_dn(dn: str) -> bool:
    # Simple regex for validating domain names
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if not re.match(domain_regex, dn):
        return False

    return True
"""
Helper functions to check if target address is IP
"""

__author__ = "Matěj Čech"

import ipaddress
import socket


def is_ipv4(address: str) -> bool:
    return address.replace('.', '').isnumeric()

def is_ipv6(address: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def reverse_ipv4(ip: str) -> str:
    addr = ipaddress.ip_address(ip)

    if addr.version != 4:
        raise TypeError("Only IPv4 addresses are supported")

    return ".".join(reversed(ip.split('.')))

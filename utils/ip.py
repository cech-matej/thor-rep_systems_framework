"""
Helper functions to check if target address is IP
"""

__author__ = "Matěj Čech"

import socket


def is_ipv4(address: str) -> bool:
    return address.replace('.', '').isnumeric()

def is_ipv6(address: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

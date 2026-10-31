"""
fp_mtu.py - MTU-based link-type fingerprinting.

Mirrors fp_mtu.c:
  fingerprint_mtu() looks up mss + IP/TCP header overhead in the MTU
  signature table and returns the link-type name.
"""

from typing import Optional
from fp_reader import mtu_sigs, MtuSigRecord

# minimum header sizes matching tcp.h
MIN_TCP4 = 40   # 20 IPv4 + 20 TCP
MIN_TCP6 = 60   # 40 IPv6 + 20 TCP


def fingerprint_mtu(pk: dict) -> Optional[str]:
    """
    Given a parsed packet dict with 'mss' and 'ip_ver', compute the
    effective MTU and look it up in the loaded MTU signature table.

    Returns the link-type label string (e.g. 'Ethernet or modem',
    'DSL', 'PPPoE') or None if not recognised.

    pk keys used: mss (int), ip_ver (int: 4 or 6)
    """
    mss = pk.get('mss', 0)
    if not mss:
        return None

    ip_ver = pk.get('ip_ver', 4)
    if ip_ver == 6:
        mtu = mss + MIN_TCP6
    else:
        mtu = mss + MIN_TCP4

    for rec in mtu_sigs:
        if rec.mtu == mtu:
            return rec.name

    return None

"""
Multi-step, possibly cross-host exploitation *flows* that don't fit the
single-request playbook model (e.g. account lifecycle with email verification).
"""

from .account_takeover import run as account_takeover
from .coupon_stacking import run as coupon_stacking

__all__ = ["account_takeover", "coupon_stacking"]

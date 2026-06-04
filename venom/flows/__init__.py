"""
Multi-step, possibly cross-host exploitation *flows* that don't fit the
single-request playbook model (e.g. account lifecycle with email verification).
"""

from .account_privilege import run as account_privilege
from .account_takeover import run as account_takeover
from .coupon_stacking import run as coupon_stacking
from .email_parser import run as email_parser
from .encryption_oracle import run as encryption_oracle
from .exceptional_input import run as exceptional_input
from .infinite_money import run as infinite_money
from .integer_overflow import run as integer_overflow
from .login_statemachine import run as login_statemachine
from .workflow_skip import run as workflow_skip

__all__ = ["account_privilege", "account_takeover", "coupon_stacking",
           "email_parser", "encryption_oracle", "exceptional_input",
           "infinite_money", "integer_overflow", "login_statemachine", "workflow_skip"]

"""Backward-compatible imports for the bounded DAST validator.

The research artifact originally called this mode ``active_local``.  The mode
identifier remains stable so earlier result-processing scripts still work, but
all execution and evidence decisions now use the bounded DAST protocol.
"""

from .bounded_dast import (
    PROTOCOL_VERSION,
    NoRedirectHandler,
    analyze_active_response,
    analyze_bounded_response,
    is_local_url_allowed,
    run_bounded_dast_validation,
    validate_alert,
)


run_active_local_validation = run_bounded_dast_validation

__all__ = [
    "PROTOCOL_VERSION",
    "NoRedirectHandler",
    "analyze_active_response",
    "analyze_bounded_response",
    "is_local_url_allowed",
    "run_active_local_validation",
    "run_bounded_dast_validation",
    "validate_alert",
]

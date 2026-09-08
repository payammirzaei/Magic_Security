from magic_security.checks.cookies import CookieSecurityCheck
from magic_security.checks.exposures import ExposureHeuristicCheck
from magic_security.checks.headers import SecurityHeaderCheck

DEFAULT_CHECKS = [
    SecurityHeaderCheck(),
    CookieSecurityCheck(),
    ExposureHeuristicCheck(),
]

__all__ = [
    "CookieSecurityCheck",
    "ExposureHeuristicCheck",
    "SecurityHeaderCheck",
    "DEFAULT_CHECKS",
]

import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/interfaces/whois_lookup.py'. Import from 'baitblocker.interfaces.whois_lookup' instead.",
    DeprecationWarning,
)

from baitblocker.interfaces.whois_lookup import *  # noqa: F401,F403

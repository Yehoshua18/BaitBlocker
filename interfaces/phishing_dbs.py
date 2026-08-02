import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/interfaces/phishing_dbs.py'. Import from 'baitblocker.interfaces.phishing_dbs' instead.",
    DeprecationWarning,
)

from baitblocker.interfaces.phishing_dbs import *  # noqa: F401,F403

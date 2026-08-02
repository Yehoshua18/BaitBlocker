import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/db/matcher.py'. Import from 'baitblocker.db.matcher' instead.",
    DeprecationWarning,
)

from baitblocker.db.matcher import *  # noqa: F401,F403

import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/db/database.py'. Import from 'baitblocker.db.database' instead.",
    DeprecationWarning,
)

from baitblocker.db.database import *  # noqa: F401,F403

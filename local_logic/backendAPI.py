import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/backend_api.py'. Import from 'baitblocker.backend_api' instead.",
    DeprecationWarning,
)

from baitblocker.backend_api import *  # noqa: F401,F403

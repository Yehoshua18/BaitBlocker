import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/core/local_analysis.py'. Import from 'baitblocker.core.local_analysis' instead.",
    DeprecationWarning,
)

from baitblocker.core.local_analysis import *  # noqa: F401,F403

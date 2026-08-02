import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/core/emailchecker.py'. Import from 'baitblocker.core.emailchecker' instead.",
    DeprecationWarning,
)

from baitblocker.core.emailchecker import *  # noqa: F401,F403

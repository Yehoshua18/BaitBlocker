import warnings

warnings.warn(
    "Module moved to 'src/baitblocker/interfaces/sandbox.py'. Import from 'baitblocker.interfaces.sandbox' instead.",
    DeprecationWarning,
)

from baitblocker.interfaces.sandbox import *  # noqa: F401,F403

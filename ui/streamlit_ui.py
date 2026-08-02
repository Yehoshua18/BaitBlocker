import warnings

warnings.warn(
    "UI moved to 'src/baitblocker/ui/streamlit_ui.py'. Import/run from 'src' or use 'baitblocker.ui.streamlit_ui' instead.",
    DeprecationWarning,
)

from baitblocker.ui.streamlit_ui import *  # noqa: F401,F403

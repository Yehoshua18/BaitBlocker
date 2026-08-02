"""Compatibility shim for the BaitBlocker package.

This project uses a `src/` layout for the canonical implementation under
`src/baitblocker`, but some tools and IDE inspections expect a top-level
`baitblocker` package to exist.

This shim extends the package search path so imports like
`baitblocker.backend_api` and `baitblocker.db.database` resolve correctly
without requiring manual `PYTHONPATH` tweaks in every environment.
"""

from __future__ import annotations

from pathlib import Path
from pkgutil import extend_path

# `__path__` is provided by the import machinery for packages; initialize it
# defensively so static analyzers and IDEs don't complain during inspection.
try:
    __path__  # type: ignore[name-defined]
except NameError:
    __path__ = []  # type: ignore[assignment]

__path__ = extend_path(__path__, __name__)

_repo_root = Path(__file__).resolve().parent.parent
_src_pkg = _repo_root / "src" / "baitblocker"
if _src_pkg.exists():
    __path__.append(str(_src_pkg))

# No eager imports here; submodules are resolved lazily from src/baitblocker.



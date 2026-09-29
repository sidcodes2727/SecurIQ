"""SecurIQ terminal package: every analysis feature, and a Gotham-style console UI, in the shell."""
import os
import sys
from pathlib import Path

__version__ = "4.0.0"

# An installed copy keeps its data in the user's home; a source checkout keeps sharing backend/data
# with the web app. SECURIQ_DATA_DIR always wins. This must run before `backend.config` is imported.
if "SECURIQ_DATA_DIR" not in os.environ:
    _backend = Path(__file__).resolve().parent.parent / "backend"
    if "site-packages" in str(_backend) or not (_backend / "data").exists() and not (_backend.parent / ".git").exists():
        os.environ["SECURIQ_DATA_DIR"] = str(Path.home() / ".securiq")

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

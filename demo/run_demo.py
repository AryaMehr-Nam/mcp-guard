"""Self-contained live demonstration of MCP-Guard active scanning and runtime proxy."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from mcp_guard.demo.run_demo import run_live_demo  # noqa: E402

VULNERABLE_SERVER_PATH = Path(__file__).resolve().parent / "vulnerable_server.py"

__all__ = ["VULNERABLE_SERVER_PATH", "run_live_demo"]

if __name__ == "__main__":
    raise SystemExit(run_live_demo())

"""Compatibility entry point for the deployed alert-source proof runner."""

from __future__ import annotations

import runpy
from pathlib import Path


# execute the production-owned proof with its original command-line arguments
def main() -> None:
    runpy.run_path(
        Path(__file__).resolve().parents[1] / "deploy/alerts/prove-sources.py",
        run_name="__main__",
    )


# preserve the historical command-line entry point without import side effects
if __name__ == "__main__":
    main()

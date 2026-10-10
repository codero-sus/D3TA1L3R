"""Allow ``python -m d3ta1l3r ...`` as an alternative to the console script."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

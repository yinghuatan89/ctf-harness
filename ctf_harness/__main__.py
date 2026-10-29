"""Allow ``python -m ctf_harness``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

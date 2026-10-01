"""Permite executar como ``python -m siemlab``.

Enables running as ``python -m siemlab``.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Bootstrap and run the local Mizan Docker Compose service."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.bootstrap import prepare_env  # noqa: E402


def main() -> int:
    try:
        token = prepare_env(ROOT)
    except (OSError, ValueError) as error:
        print("Could not prepare local configuration: %s" % error, file=sys.stderr)
        return 2

    if token:
        print("Created a private Mizan installation-owner token. Copy it now; it will not be printed again:")
        print(token)
    else:
        print("Using this installation's existing private configuration; token not displayed.")
    print("The local AES-GCM encryption key is stored in .env and is never printed.")

    command = ["docker", "compose", "up", "--build"] + sys.argv[1:]
    try:
        result = subprocess.run(command, cwd=str(ROOT), check=False)
    except FileNotFoundError:
        print(
            "Docker Engine and the Docker Compose v2 plugin are required. "
            "For a Python-only run, use: python3 server.py",
            file=sys.stderr,
        )
        return 127
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

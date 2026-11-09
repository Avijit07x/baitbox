import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from baitbox.cli import run

if __name__ == "__main__":
    sys.exit(run())

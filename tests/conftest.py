import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "baitbox" / "scripts"
sys.path.insert(0, str(SCRIPTS))


def sandbox_available():
    if not (shutil.which("bwrap") and shutil.which("strace") and shutil.which("node")):
        return False
    try:
        p = subprocess.run(
            ["strace", "-f", "-o", "/dev/null", "bwrap", "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "true"],
            capture_output=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0


SANDBOX = sandbox_available()
needs_sandbox = pytest.mark.skipif(not SANDBOX, reason="bubblewrap, strace or node unavailable, or user namespaces blocked")


@pytest.fixture
def scripts_dir():
    return SCRIPTS


def write(root, rel, content, mode=None):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    if mode is not None:
        p.chmod(mode)
    return p

import subprocess
from pathlib import Path

BOX = Path(__file__).resolve().parent / "box.sh"


def box(mode, root, box_dir, seconds, command):
    p = subprocess.run(
        ["bash", str(BOX), mode, str(root), str(box_dir), str(seconds), command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
    )
    return {"mode": mode, "exit": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()[-2000:]}

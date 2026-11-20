"""
Bootstraps a private virtual environment for the Visual Expert MCP server, then runs it.

- The venv lives in VE_VENV_DIR (the plugin's persistent data dir), so it survives plugin updates.
- It is (re)built when requirements.txt changes.
- All bootstrap output goes to stderr: stdout is the MCP protocol channel.
"""

import hashlib
import os
import subprocess
import sys
import venv
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQS = HERE / "requirements.txt"
SERVER = HERE / "server.py"


def log(msg: str) -> None:
    print(f"[visual-expert] {msg}", file=sys.stderr, flush=True)


def venv_python(d: Path) -> Path:
    return d / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_venv() -> Path:
    vdir = os.environ.get("VE_VENV_DIR", "")
    d = Path(vdir) if vdir and not vdir.startswith("${") else HERE / ".venv"
    py = venv_python(d)
    want = hashlib.sha256(REQS.read_bytes()).hexdigest()
    stamp = d / ".requirements.sha256"
    if py.exists() and stamp.exists() and stamp.read_text().strip() == want:
        return py
    log(f"Setting up Python environment in {d} (first run or dependency change)...")
    if not py.exists():
        venv.EnvBuilder(with_pip=True, clear=True).create(d)
    subprocess.check_call(
        [str(py), "-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", str(REQS)],
        stdout=sys.stderr,
    )
    stamp.write_text(want)
    log("Environment ready.")
    return py


def main() -> int:
    if sys.version_info < (3, 10):
        log(f"Python 3.10+ is required (found {sys.version.split()[0]}).")
        return 1
    py = ensure_venv()
    # Inherit stdin/stdout so the MCP stdio stream passes straight through.
    return subprocess.call([str(py), str(SERVER), *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())

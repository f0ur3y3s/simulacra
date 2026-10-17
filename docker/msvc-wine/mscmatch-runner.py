#!/usr/bin/env python3
"""In-container compile runner. Reads one JSON job on stdin, writes one JSON result on stdout.

Job:    {"files": {"name": "text", ...}, "args": ["/c", ...], "obj": "src.obj", "timeout": 20,
         "outputs": ["extra.map", ...],                       (optional)
         "binary_files": {"name": "<base64>", ...}}           (optional, e.g. objects to link)
Result: {"ok": bool, "returncode": int, "stdout": str, "stderr": str,
         "obj_b64": str | null, "outputs_b64": {name: str | null}, "elapsed": float,
         "timed_out": bool}

Every job runs in the same fixed directory (/work/job) so that paths embedded in the object
(e.g. /Z7 debug info) are identical across workers and runs.
"""

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time

CL = "/opt/msvc/bin/x64/cl"
JOB_DIR = "/work/job"


def _job_path(name: str) -> str:
    """Path under JOB_DIR for a relative job file name; rejects anything escaping it."""
    parts = name.replace("\\", "/").split("/")
    if name.startswith(("/", "\\")) or any(p in ("", ".", "..") for p in parts):
        raise SystemExit(f"bad file name {name!r}")
    path = os.path.join(JOB_DIR, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def main() -> None:
    job = json.load(sys.stdin)
    shutil.rmtree(JOB_DIR, ignore_errors=True)
    os.makedirs(JOB_DIR)
    for name, text in job["files"].items():
        with open(_job_path(name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    for name, b64 in job.get("binary_files", {}).items():
        with open(_job_path(name), "wb") as f:
            f.write(base64.b64decode(b64))

    timed_out = False
    start = time.monotonic()
    proc = subprocess.Popen(
        [CL, *job["args"]],
        cwd=JOB_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=job.get("timeout", 20))
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        subprocess.run(["pkill", "-9", "-f", "cl.exe"], check=False)
        out, err = proc.communicate()
    elapsed = time.monotonic() - start

    obj_path = os.path.join(JOB_DIR, job["obj"])
    obj_b64 = None
    if proc.returncode == 0 and not timed_out and os.path.exists(obj_path):
        with open(obj_path, "rb") as f:
            obj_b64 = base64.b64encode(f.read()).decode("ascii")

    outputs = {}
    for name in job.get("outputs", []):
        path = os.path.join(JOB_DIR, name)
        ok_file = proc.returncode == 0 and not timed_out and os.path.isfile(path)
        if ok_file:
            with open(path, "rb") as f:
                outputs[name] = base64.b64encode(f.read()).decode("ascii")
        else:
            outputs[name] = None

    json.dump(
        {
            "outputs_b64": outputs,
            "ok": obj_b64 is not None,
            "returncode": proc.returncode,
            "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace"),
            "obj_b64": obj_b64,
            "elapsed": elapsed,
            "timed_out": timed_out,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()

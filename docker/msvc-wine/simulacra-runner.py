#!/usr/bin/env python3
"""In-container compile runner. Reads one JSON job on stdin, writes one JSON result on stdout.

Job:    {"files": {"name": "text", ...}, "args": ["/c", ...], "obj": "src.obj", "timeout": 20,
         "outputs": ["extra.map", ...],                       (optional)
         "binary_files": {"name": "<base64>", ...},           (optional, e.g. objects to link)
         "exec": ["cmake", "-P", "x.cmake"],                    (optional: run this, not cl)
         "output_globs": ["out/**/*.i", ...]}                   (optional, relative to the job)
Result: {"ok": bool, "returncode": int, "stdout": str, "stderr": str,
         "obj_b64": str | null, "outputs_b64": {name: str | null}, "elapsed": float,
         "timed_out": bool}

With "exec", `ok` reflects the exit status and "obj" may be empty; outputs matched by
"output_globs" are returned in "outputs_b64" alongside the named ones.

Every job runs in the same fixed directory (/work/job) so that paths embedded in the object
(e.g. /Z7 debug info) are identical across workers and runs.
"""

import base64
import glob
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
    argv = job["exec"] if job.get("exec") else [CL, *job["args"]]
    env = dict(os.environ, PATH="/opt/msvc/bin/x64:" + os.environ.get("PATH", ""))
    proc = subprocess.Popen(
        argv,
        env=env,
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

    obj_path = os.path.join(JOB_DIR, job.get("obj") or "")
    obj_b64 = None
    if job.get("obj") and proc.returncode == 0 and not timed_out and os.path.isfile(obj_path):
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
    for pattern in job.get("output_globs", []):
        for path in glob.glob(os.path.join(JOB_DIR, pattern), recursive=True):
            if os.path.isfile(path):
                rel = os.path.relpath(path, JOB_DIR).replace(os.sep, "/")
                with open(path, "rb") as f:
                    outputs[rel] = base64.b64encode(f.read()).decode("ascii")

    ok = obj_b64 is not None
    if job.get("exec"):
        ok = proc.returncode == 0 and not timed_out

    json.dump(
        {
            "outputs_b64": outputs,
            "ok": ok,
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

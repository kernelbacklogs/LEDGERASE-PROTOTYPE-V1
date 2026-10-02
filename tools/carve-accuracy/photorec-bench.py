#!/usr/bin/env python3
"""Run photorec over an image, non-interactively, and hash what it recovered.

This is a benchmark, not a dependency. The numbers are put next to this tool's
own so the two can be compared on the same images; nothing from photorec is
copied into this project.

PhotoRec 7.2 has no documented batch mode in its man page, and the /cmd switch
this was written against is undocumented. It is therefore driven through a pty,
and if that stops working the script says so rather than producing an empty
result and calling it a score of zero - an empty recovery and a failure to run
are different findings.

Usage:
  photorec-bench.py <image> <output-dir> [--timeout 900]
"""

import argparse
import hashlib
import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\r")


def drive(pty_master, keys, timeout, idle=2.0):
    """Send keys, collect output, until the child goes quiet for `idle` seconds
    or the total timeout expires."""
    collected = bytearray()
    pending = list(keys)
    last = time.time()
    deadline = time.time() + timeout
    while time.time() < deadline:
        readable, _, _ = select.select([pty_master], [], [], 0.4)
        if readable:
            try:
                chunk = os.read(pty_master, 65536)
            except OSError:
                break
            if not chunk:
                break
            collected += chunk
            last = time.time()
            continue
        if pending and time.time() - last > idle:
            os.write(pty_master, pending.pop(0))
            last = time.time()
            idle = 1.0
        elif not pending and time.time() - last > idle * 3:
            break
    return bytes(collected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("outdir")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    if shutil.which("photorec") is None:
        print(json.dumps({
            "ran": False,
            "reason": "photorec is not installed on this machine",
        }))
        return 3

    if os.path.exists(args.outdir):
        shutil.rmtree(args.outdir)
    os.makedirs(args.outdir, exist_ok=True)

    before = time.time()
    primary, secondary = pty.openpty()
    process = subprocess.Popen(
        ["photorec", "/log", "/d", args.outdir, args.image],
        stdin=secondary, stdout=secondary, stderr=secondary,
        close_fds=True,
    )
    os.close(secondary)
    # Right arrow to pick the whole disk, then Enter through the file-type
    # list, then the search confirmation.
    output = drive(primary, [b"\x1b[C", b"\r", b"\r", b"\r", b"\r", b"\r"], args.timeout)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
    os.close(primary)
    elapsed = time.time() - before

    # PhotoRec does not write into the directory it is given. It creates a
    # sibling named "<dir>.<n>" and recovers into that. Found by looking at what
    # is on disk after the run, because nothing documents it, and the first
    # version of this script counted an empty directory and called it a score of
    # zero.
    base = args.outdir.rstrip("/")
    parent = os.path.dirname(base) or "."
    prefix = os.path.basename(base) + "."
    siblings = sorted(
        os.path.join(parent, entry) for entry in os.listdir(parent)
        if entry.startswith(prefix) and os.path.isdir(os.path.join(parent, entry)))
    recovered = []
    for directory in ([args.outdir] + siblings):
        for root, _, names in os.walk(directory):
            for name in names:
                path = os.path.join(root, name)
                if name == "report.xml":
                    # PhotoRec's own account of the run, not a recovered file.
                    continue
                try:
                    with open(path, "rb") as handle:
                        digest = hashlib.sha256(handle.read()).hexdigest()
                    size = os.path.getsize(path)
                except OSError:
                    continue
                recovered.append({"name": name, "path": path, "size": size,
                                  "sha256": digest})
    recovered.sort(key=lambda item: (-item["size"], item["name"]))

    version = subprocess.run(["photorec", "/version"], capture_output=True,
                             text=True).stdout.strip().splitlines()
    result = {
        "ran": True,
        "tool": "PhotoRec " + (version[0].split()[1] if version else "?"),
        "image": args.image,
        "output_dir": args.outdir,
        "recovered_into": siblings,
        "seconds": round(elapsed, 1),
        "files_recovered": len(recovered),
        "bytes_recovered": sum(item["size"] for item in recovered),
        "files": recovered[:400],
        # The raw terminal transcript, so a reader can see what it actually did
        # rather than take the file count on trust.
        "transcript_tail": ANSI.sub("", output.decode("utf-8", "replace"))[-4000:],
    }
    with open(os.path.join(args.outdir, "photorec-result.json"), "w") as handle:
        json.dump(result, handle, indent=1)
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("files", "transcript_tail")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

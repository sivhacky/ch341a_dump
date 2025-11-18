#!/usr/bin/env python3
"""
ch341a_dump.py

Safe wrapper to dump SPI flash via CH341A using flashrom.
- Read-only by default (no erase/write).
- Produces: <output>.bin, <output>.log, <output>.meta.json
- Optional re-read verification.

Usage:
    python3 ch341a_dump.py --output firmware_dump.bin --verify

Prereqs:
    - flashrom installed and accessible in PATH
      (https://www.flashrom.org/Flashrom)
    - CH341A connected and supported by your flashrom build
"""

from __future__ import annotations
import argparse
import subprocess
import shutil
import sys
import os
import hashlib
import json
import time
from datetime import datetime
from typing import Tuple

# -------------------------
# Configuration / Defaults
# -------------------------
FLASHROM_CMD = "flashrom"
PROGRAMMER = "ch341a_spi"   # flashrom programmer string for CH341A SPI
DEFAULT_BAUD = None         # not used for ch341a_spi; kept for possible extensions
READ_TIMEOUT = 3600         # seconds; keep long for large chips

# -------------------------
# Utility functions
# -------------------------
def check_flashrom_available() -> bool:
    return shutil.which(FLASHROM_CMD) is not None

def run_flashrom_read(output_file: str, extra_args: list[str] = []) -> Tuple[int,str,str]:
    """
    Run flashrom read command: flashrom -p ch341a_spi -r <output_file> [extra args]
    Returns (returncode, stdout, stderr)
    """
    cmd = [FLASHROM_CMD, "-p", PROGRAMMER, "-r", output_file] + extra_args
    env = os.environ.copy()

    # Start subprocess and capture output (stream to log)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    try:
        stdout, stderr = proc.communicate(timeout=READ_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return (proc.returncode or 1, stdout, "TimeoutExpired: " + stderr)
    return (proc.returncode, stdout, stderr)

def file_hashes(path: str) -> dict:
    """Return dict with sha256 and md5 of file at path."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size_bytes": os.path.getsize(path)}

def timestamp() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# -------------------------
# Main workflow
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Safe SPI flash dump using CH341A via flashrom (read-only).")
    parser.add_argument("--output", "-o", required=True, help="Output filename for firmware dump (e.g. firmware.bin)")
    parser.add_argument("--verify", "-v", action="store_true", help="Re-read after dump and verify bytes match.")
    parser.add_argument("--verbose", action="store_true", help="Print detailed flashrom output to console.")
    parser.add_argument("--extra-args", nargs="*", default=[], help="Extra args to pass to flashrom (be careful).")
    args = parser.parse_args()

    out_file = args.output
    log_file = f"{out_file}.log"
    meta_file = f"{out_file}.meta.json"

    # Safety check: Ensure not overwriting existing important file
    if os.path.exists(out_file):
        print(f"[!] Output file {out_file} already exists. Move or remove it before running to avoid overwrite.")
        sys.exit(1)

    if not check_flashrom_available():
        print("[!] flashrom not found in PATH. Install flashrom and ensure it's the version supporting ch341a_spi.")
        print("    Example (Debian/Ubuntu): sudo apt-get install flashrom")
        sys.exit(1)

    print("[*] flashrom found. Beginning dump process (read-only).")
    start_time = time.time()

    # Run flashrom read
    rc, stdout, stderr = run_flashrom_read(out_file, extra_args=args.extra_args)

    # Write log
    with open(log_file, "w", encoding="utf-8") as lf:
        lf.write(f"### ch341a_dump log\n")
        lf.write(f"timestamp: {timestamp()}\n")
        lf.write(f"cmd: {FLASHROM_CMD} -p {PROGRAMMER} -r {out_file} {' '.join(args.extra_args)}\n\n")
        lf.write("=== STDOUT ===\n")
        lf.write(stdout or "")
        lf.write("\n\n=== STDERR ===\n")
        lf.write(stderr or "")
    if rc != 0:
        print(f"[!] flashrom returned non-zero exit code: {rc}. See {log_file} for full output.")
        sys.exit(2)

    if not os.path.exists(out_file):
        print(f"[!] flashrom reported success but {out_file} not found. Check {log_file}.")
        sys.exit(3)

    duration = time.time() - start_time
    print(f"[+] Dump complete: {out_file} ({duration:.1f}s). Computing hashes...")

    hashes = file_hashes(out_file)
    meta = {
        "tool": "ch341a_dump.py",
        "flashrom_programmer": PROGRAMMER,
        "flashrom_cmd": FLASHROM_CMD,
        "output_file": out_file,
        "log_file": log_file,
        "dump_time_utc": timestamp(),
        "duration_seconds": duration,
        "hashes": hashes,
        "flashrom_stdout_excerpt": (stdout[:1000] if stdout else ""),
        "flashrom_stderr_excerpt": (stderr[:1000] if stderr else ""),
    }

    # Optional verify: re-read to temp and compare
    if args.verify:
        temp_read = out_file + ".re-read"
        print("[*] Performing re-read for verification...")
        rc2, stdout2, stderr2 = run_flashrom_read(temp_read, extra_args=args.extra_args)
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write("\n\n### Re-read log\n")
            lf.write("=== STDOUT (re-read) ===\n")
            lf.write(stdout2 or "")
            lf.write("\n\n=== STDERR (re-read) ===\n")
            lf.write(stderr2 or "")

        if rc2 != 0 or not os.path.exists(temp_read):
            print(f"[!] Re-read failed (rc={rc2}). See {log_file}.")
            meta["verify"] = {"status": "re-read-failed", "rc": rc2}
        else:
            print("[*] Computing hashes for re-read and comparing...")
            hashes2 = file_hashes(temp_read)
            meta["verify"] = {
                "re_read_file": temp_read,
                "hashes": hashes2,
                "match": hashes2["sha256"] == hashes["sha256"]
            }
            if meta["verify"]["match"]:
                print("[+] Verification successful: re-read image matches initial dump.")
                # remove temporary re-read file to keep repo clean (optional)
                os.remove(temp_read)
            else:
                print("[!] Verification failed: re-read image does not match initial dump. See log for details.")

    # Write metadata
    with open(meta_file, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)

    print(f"[+] Metadata written to {meta_file}")
    print(f"[+] Log written to {log_file}")
    print("[*] All done. Keep dumps secure and only use them in authorized workflows.")

if __name__ == "__main__":
    main()

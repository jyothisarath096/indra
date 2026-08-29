#!/usr/bin/env python3
"""Minimal cc-driver argument adapter for Rust's self-contained musl CRT."""
import os
import subprocess
import sys

sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
lld = os.path.join(sysroot, "lib/rustlib/aarch64-apple-darwin/bin/rust-lld")
out = [lld, "-flavor", "gnu"]
drop = {"-m64", "-nostartfiles", "-nodefaultlibs"}
for arg in sys.argv[1:]:
    if arg in drop:
        continue
    if arg.startswith("-Wl,"):
        out.extend(arg[4:].split(","))
    else:
        out.append(arg)
os.execv(lld, out)

#!/usr/bin/env python3
import hashlib, pathlib, sys

paths = [pathlib.Path(value) for value in sys.argv[1:]]
if len(paths) < 2:
    raise SystemExit("usage: compare.py RESULTS RESULTS [...]")
payloads = []
for path in paths:
    data = path.read_bytes()
    print(f"{path}: {hashlib.sha256(data).hexdigest()} ({len(data)} bytes)")
    payloads.append(data)
if any(value != payloads[0] for value in payloads[1:]):
    raise SystemExit("FAIL: canonical result artifacts differ")
print("PASS: canonical result artifacts are byte-identical")

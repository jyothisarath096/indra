#!/usr/bin/env python3
"""Fail if the normative consensus build policy drifts from repository inputs."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "ci" / "consensus-build-matrix.toml"
DOC_PATH = ROOT / "docs" / "CONSENSUS_BUILD_MATRIX.md"


def load_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def fail(message: str) -> None:
    raise SystemExit(f"consensus build policy error: {message}")


def main() -> None:
    matrix = load_toml(MATRIX_PATH)
    toolchain = load_toml(ROOT / "rust-toolchain.toml")["toolchain"]
    cargo = load_toml(ROOT / "Cargo.toml")
    document = DOC_PATH.read_text(encoding="utf-8")

    expected_channel = matrix["toolchain"]["rustc_version"]
    if toolchain.get("channel") != expected_channel:
        fail("rust-toolchain.toml does not match the matrix compiler")
    if toolchain.get("profile") != "minimal":
        fail("the audited toolchain profile must remain minimal")

    rustc_version = subprocess.run(
        ["rustc", "-vV"], check=True, text=True, capture_output=True
    ).stdout
    cargo_version = subprocess.run(
        ["cargo", "-vV"], check=True, text=True, capture_output=True
    ).stdout
    required_toolchain_markers = (
        (rustc_version, f"release: {expected_channel}"),
        (rustc_version, f"commit-hash: {matrix['toolchain']['rustc_commit']}"),
        (rustc_version, f"LLVM version: {matrix['toolchain']['llvm_version']}"),
        (cargo_version, f"release: {matrix['toolchain']['cargo_version']}"),
        (cargo_version, f"commit-hash: {matrix['toolchain']['cargo_commit']}"),
    )
    for output, marker in required_toolchain_markers:
        if marker not in output:
            fail(f"active toolchain does not contain {marker!r}")

    release = cargo.get("profile", {}).get("release", {})
    expected_release = {
        "opt-level": 3,
        "lto": True,
        "codegen-units": 1,
        "panic": "abort",
    }
    for key, expected in expected_release.items():
        if release.get(key) != expected:
            fail(f"release profile {key!r} is {release.get(key)!r}, expected {expected!r}")

    lock_digest = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    if lock_digest != matrix["build"]["cargo_lock_sha256"]:
        fail("Cargo.lock changed; review dependencies and update the audited matrix digest")

    targets = [entry["target"] for entry in matrix["platform"]]
    if len(targets) != len(set(targets)) or len(targets) != 3:
        fail("matrix must contain exactly three unique target triples")
    for target in targets:
        if target not in document:
            fail(f"documentation omits matrix target {target}")

    forbidden = ("windows", "-pc-windows-", "target-cpu=native")
    matrix_text = MATRIX_PATH.read_text(encoding="utf-8").lower()
    if any(token in matrix_text for token in forbidden):
        fail("matrix contains a forbidden platform or host-specific CPU policy")

    print("consensus build policy: OK")
    print(f"rustc: {expected_channel} ({matrix['toolchain']['rustc_commit']})")
    print("targets:")
    for target in targets:
        print(f"  {target}")
    print(f"Cargo.lock sha256: {lock_digest}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as error:
        fail(str(error))

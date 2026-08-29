# RFC 9381 ELL2 differential audit harness

This non-production harness compares INDRA against Leo Reyzin's independent,
insecure reference/test-vector implementation. Passing establishes protocol
mapping agreement; it does **not** establish implementation security.

Pinned reference:

- repository: `https://github.com/reyzin/ecvrf.git`
- commit: `917883bc5fa4dfb069bc40ed7cf8ba5d988bedf1`

Prerequisites on macOS/Homebrew:

```sh
brew install ntl gmp
```

Run from any directory:

```sh
./audit_evidence/03_vrf_differential/run.sh
```

The script clones the reference into a temporary directory, verifies its exact
commit, builds a machine-readable adapter with `c++ -std=c++11 -O2` against
NTL/GMP, and runs the release-mode Rust driver. The driver first requires all
three official RFC 9381 ELL2 vectors to match, then derives 1,000 cases from
fixed seed `0x494e4452412d5652`. Message lengths cycle through 0, 1, 7, 31, 32,
63, 128, 255, and 1024 bytes. It checks public keys, proofs, outputs, both
prove/verify directions, proof-to-hash, and 9,000 malformed cases.

On the first disagreement, the harness writes `mismatch.txt` beside this file
with the complete reproducer and aborts. The reference is never linked into an
INDRA binary and is not a workspace or shipping Cargo dependency.

The reference adapter's effective build command is:

```sh
c++ -std=c++11 -O2 \
  -I$REFERENCE_DIR -I/opt/homebrew/include \
  reference_cli.cpp $REFERENCE_DIR/sha512.c \
  -L/opt/homebrew/lib -lntl -lgmp -o reference_cli
```

`run.sh` also prints the INDRA Git commit and the SHA-256 of the exact VRF
source file tested, so a run remains identifiable when the worktree contains
uncommitted audit-only changes.

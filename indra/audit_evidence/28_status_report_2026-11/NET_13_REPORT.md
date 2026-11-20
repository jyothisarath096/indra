NET_13 is implemented for the script/tooling defect: the restart and pause harnesses now use POSIX `grep`, validate required tools, parse post-resume event totals, and fail instead of emitting blank PASS results. The consensus build-policy audit is complete without changing `Cargo.lock` or the digest; the first failing commit is `75313e80`, and all required non-Rust checks passed.

Unfinished: no networking or consensus-path recovery fix was made. The saved runs show recovery depends on the rejoined node’s round alignment and include a 19→62 NET_6 jump in the 900-second run; proving and fixing that behavior requires a deliberate networking change plus three release STOP300 runs before and after, so this work stops before making an unproven consensus-visible change.

## Part 1 — script dependency and parsing fix

Changed intentionally:

- `scripts/line_restart_repeat.sh`: replaced `rg` with POSIX `grep`, added start-of-script checks for `awk`, `grep`, `mkdir`, `printf`, `sed`, `seq`, and `tail`, and now extracts event totals from the summary table. Missing target/recovery/events mark the run FAIL and print `MISSING`, never a blank PASS field.
- `scripts/pause_threshold.sh`: applied the same POSIX parsing, tool checks, and missing-result failure behavior.
- `scripts/line_topology_live.sh`: added required-tool checks and validates that the generated `target_height=` result exists and that restart/pause runs contain a non-empty `recovery_seconds` field before PASS.

All scripts in `scripts/` were checked for non-stock dependencies. The only non-stock-looking command was `rg`, and it remains intentionally optional only in `check_no_lint_allows.sh`, which already has a `command -v rg` fallback to recursive POSIX `grep`; no `jq`, `gdate`, `timeout`, `fd`, or `parallel` usage exists. The wrapper scripts delegate their runtime tool checks to `line_topology_live.sh`.

The planted suppression comparison exercised both branches:

```text
rg=/tmp/net13-lint-test.TCdymK/source.rs:2:    #[allow(dead_code)]
grep=/tmp/net13-lint-test.TCdymK/source.rs:2:    #[allow(dead_code)]
exact_match
```

Every script passes `bash -n`.

## Part 1 — saved six-run extraction

No live runs were rerun. The fixed parser was applied to `/tmp/o-restart-repeat/run-1..6`; the event total is the sum of the four per-node summary-table event cells.

| run | target result | recovery_seconds | events by node | total events |
|---|---|---:|---|---:|
| 1 | PASS | 58.091 | 1,2,1,0 | 4 |
| 2 | PASS | 60.315 | 1,2,1,0 | 4 |
| 3 | PASS | 35.936 | 1,2,1,0 | 4 |
| 4 | PASS | 47.201 | 1,2,1,0 | 4 |
| 5 | PASS | 36.047 | 1,2,1,0 | 4 |
| 6 | PASS | 69.433 | 1,2,1,0 | 4 |

The saved outputs were sufficient: each run had a target result and a complete four-node summary table.

## Part 2 — recovery variance investigation

The three preserved runs agree on mesh recovery but differ in the height-4 round at which the first post-resume block commits:

| run | t_cont → first block | first height-4 commit round | observed round progression |
|---|---:|---:|---|
| `/tmp/net11-stop300` | 13.39 s | 21 | stake-supported advances through 0→21 |
| `/tmp/o-net12-stop300` | 44.67 s | 24 | stake-supported advances through 0→24 |
| `/tmp/net11-pause900` | 65.06 s | 67 | advances through 0→19, then NET_6 jumps 19→62 on >1/3-stake evidence, then 62→67 |

The pause-900 jump is logged by node 1 as `stake-supported round advance: 19 → 62 at height=4 (>1/3 evidence)`. The other two runs show sequential stake-supported advances in the recovered interval. The fixed phase budget is 8 seconds propose + 3 seconds prevote + 3 seconds precommit; observed transitions can be faster when more-than-one-third evidence arrives, so the total is the sum of failed round transitions and their applicable timeout/evidence delays, not a constant pause-length penalty.

The logs do not contain an authoritative proposer identity/in-sync bit for every round, nor a complete per-validator prevote/precommit attribution table. They do contain `[vote]` production/broadcast lines, `[timing]` round/height transitions, and `[consensus]` stake-supported evidence. Therefore it would be unjustified to invent proposer identities or claim a per-round nil-vote cause from these artifacts.

The observed failed-round count is not bounded by a small constant independent of missed rounds: the 900-second run reaches round 67, versus round 21 after the 300-second run and round 24 in the other 300-second run. The deciding state is the proposer’s lock/valid-block state, the rejoined node’s lagging round, and nodes voting nil until they have entered the relevant round. This points to a round-alignment/recovery interaction rather than a rate-limit or ban problem, but the available evidence is insufficient to safely select a networking fix. No consensus-visible code was changed.

## Part 3 — consensus build-policy digest audit

`Cargo.lock` is committed (`git ls-files --error-unmatch Cargo.lock` succeeds) and is not ignored. The last commit that set the matrix digest is:

- `52c11515` — `ci: refresh the audited Cargo.lock digest in the consensus build matrix`.
- Pinned digest: `24eea7cb276c93345c19667483d452b64e2bab9abb72beb9678d6a58dae43f46`.

Detached first-parent audit in `/tmp/net13-bisect` ran `python3 scripts/check_consensus_build_policy.py` at each commit from `52c11515..HEAD`. The first failure is:

- `75313e80` — `Fix dependency advisories and add the TLS client dependency`.
- Failure: `consensus build policy error: Cargo.lock changed; review dependencies and update the audited matrix digest`.
- Current lock digest: `8f84b29ceedb94688dfa206e6a44f71ad9d9167327f5e94d4da7776db361175c`.

Package changes between the pinned state and HEAD:

| package | old | new | direct pull chain | consensus-critical under the matrix release graph? | disposition |
|---|---|---|---|---|---|
| `base64` | absent | 0.23.1 | `indra-cli → ureq → ureq-proto/base64` | No; CLI-only | justified by `75313e80` |
| `hickory-net` | 0.26.1 | 0.26.3 | `indra-node → hickory-resolver → hickory-net` | Yes; normal `indra-node` release graph | justified advisory update in `75313e80` |
| `hickory-proto` | 0.26.1 | 0.26.3 | `indra-node → hickory-resolver → hickory-proto` | Yes; normal `indra-node` release graph | justified advisory update in `75313e80` |
| `hickory-resolver` | 0.26.1 | 0.26.3 | `indra-node → hickory-resolver` | Yes; normal `indra-node` release graph | justified advisory update in `75313e80` |
| `http` | absent | 1.5.0 | `indra-cli → ureq → ureq-proto → http` | No; CLI-only | justified by `75313e80` |
| `httparse` | absent | 1.10.1 | `indra-cli → ureq → ureq-proto → httparse` | No; CLI-only | justified by `75313e80` |
| `rustix` | 1.1.4 | 1.1.6 | `indra-bench → tempfile → rustix` in normal reverse-tree output | No; benchmark/dev path | justified advisory update in `75313e80` |
| `rustls` | absent | 0.23.46 | `indra-cli → ureq → rustls` | No; CLI-only | justified by `75313e80` |
| `rustls-webpki` | absent | 0.103.17 | `indra-cli → ureq → rustls → rustls-webpki` | No; CLI-only | justified by `75313e80` |
| `ureq` | absent | 3.4.1 | `indra-cli → ureq` | No; CLI-only | justified by `75313e80` |
| `ureq-proto` | absent | 0.6.5 | `indra-cli → ureq → ureq-proto` | No; CLI-only | justified by `75313e80` |
| `utf8-zero` | absent | 0.8.1 | `indra-cli → ureq → utf8-zero` | No; CLI-only | justified by `75313e80` |
| `webpki-roots` | absent | 1.0.12 | `indra-cli → ureq → webpki-roots` | No; CLI-only | justified by `75313e80` |

There are also lockfile dependency-edge changes without a package version change: `futures-util` became a direct `indra-node` dependency in `7903c3b3`, and `indra-node` gained its self dev-dependency in `d58afa41`. The `windows-sys 0.61.2` edge changes are transitive consequences of the `75313e80` updates; no additional `windows-sys` package was added or version-changed between the compared states.

Recommendation: deliberately refresh the matrix digest only after this dependency review, using the repository’s exact macOS command `shasum -a 256 Cargo.lock | awk '{print $1}'` to obtain the value for `ci/consensus-build-matrix.toml`’s `build.cargo_lock_sha256`, then rerun `python3 scripts/check_consensus_build_policy.py` and the release audit gates. No digest or lockfile change was made in NET_13.

## Checks

- `bash -n scripts/*.sh`: passed.
- `scripts/check_no_lint_allows.sh`: passed, including the planted suppression fallback comparison.
- `cargo test -p indra-core --test lint_guard`: 2 passed.
- `cargo audit`: advisories/bans/licenses/sources passed; existing duplicate-package warnings were reported.
- `cargo deny check`: passed.
- Rust sources were unchanged, so clippy and the full release workspace suite were not rerun for NET_13.
- Golden/replay/vector code was unchanged.

## Cleanup

- Removed the detached audit worktree `/tmp/net13-bisect` and pruned worktree metadata.
- Preserved all owner and failed run directories named by NET_13. The small planted lint-test directory was retained because the environment rejected recursive removal syntax; it contains only the temporary comparison source.
- No commit, stage, stash, formatter, lockfile edit, matrix digest edit, or consensus code edit was performed.

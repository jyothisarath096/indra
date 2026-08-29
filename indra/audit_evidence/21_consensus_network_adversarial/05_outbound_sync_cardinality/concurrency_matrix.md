# Concurrency and cardinality harness notes

The production node owns sync and outbound mutations in serialized event-loop
threads; shared discovery maps and cooldowns are protected by `Mutex`. No
production race or double-spend was reproduced in the available deterministic
tests. The harness model exercised 200,000 advertised addresses (accepted set
remained 256), 200,000 IPv6/port variants (same bound), 200 validator IDs per
authority epoch, and 200,000 sequential height labels against the admission
preconditions. The last case cannot be injected directly: `note_expensive_failure`
is reached only after a selected, authenticated sync candidate and a bounded
request/provisional flow. It nevertheless identifies stale outer height keys as
an observability/maintenance risk.

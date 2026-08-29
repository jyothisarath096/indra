# Q768 independent mathematical oracle

- INDRA revision: `b6404ccacc508d92a022f50ad1af3da4d4e31a02`
- `sortition.rs` SHA-256: `5a305765d29a28b2e65f763b62c80d17e7cd90010058e12ac5635d1a0e5082ef`
- Oracle: MPFR via Rug, directed interval arithmetic, initial precision 2048 bits, adaptive through 32768 bits
- Structural independence: direct evaluation of `1-exp((w/W)*ln(1-F/2^64))`; no INDRA series or Q768 rounding logic reused
- Runtime: 48.605s
- Maximum precision required: 2048 bits

## Threshold contract

- Exhaustive cases (`W=1..=200`, all `w`, 10 F values): 201000
- Random/extreme cases: 10006 (6 fixed extreme + 10000 fixed-seed random)
- Difference 0: 211773
- Difference 1: 2039
- Difference >1: 0
- Production above ideal: 0

## Full-stake invariant

- Exact: 0
- One below: 35

| F | W | ideal-production |
|---:|---:|---:|
| 1 | 1 | 1 |
| 1 | 200 | 1 |
| 1 | 4294967295 | 1 |
| 1 | 18446744073709551614 | 1 |
| 1 | 18446744073709551615 | 1 |
| 2 | 1 | 1 |
| 2 | 200 | 1 |
| 2 | 4294967295 | 1 |
| 2 | 18446744073709551614 | 1 |
| 2 | 18446744073709551615 | 1 |
| 3 | 1 | 1 |
| 3 | 200 | 1 |
| 3 | 4294967295 | 1 |
| 3 | 18446744073709551614 | 1 |
| 3 | 18446744073709551615 | 1 |
| 4294967295 | 1 | 1 |
| 4294967295 | 200 | 1 |
| 4294967295 | 4294967295 | 1 |
| 4294967295 | 18446744073709551614 | 1 |
| 4294967295 | 18446744073709551615 | 1 |
| 4294967296 | 1 | 1 |
| 4294967296 | 200 | 1 |
| 4294967296 | 4294967295 | 1 |
| 4294967296 | 18446744073709551614 | 1 |
| 4294967296 | 18446744073709551615 | 1 |
| 9223372036854775807 | 1 | 1 |
| 9223372036854775807 | 200 | 1 |
| 9223372036854775807 | 4294967295 | 1 |
| 9223372036854775807 | 18446744073709551614 | 1 |
| 9223372036854775807 | 18446744073709551615 | 1 |
| 9223372036854775808 | 1 | 1 |
| 9223372036854775808 | 200 | 1 |
| 9223372036854775808 | 4294967295 | 1 |
| 9223372036854775808 | 18446744073709551614 | 1 |
| 9223372036854775808 | 18446744073709551615 | 1 |

## Eligibility endpoints

6 representative thresholds passed `T-1`, `T`, `T+1`.

## Monotonicity

2768 dense/wide checks passed for stake and F monotonicity.

## Split/merge

20 representative partitions through 200 validators passed the direct 4096-bit MPFR ideal no-election identity check. The maximum exact production finite-grid deviation had a 101896-bit numerator over denominator `2^102400`, hence is strictly below `2^-504`; reproducer: `F=1, 200 parts of weight 1, W=200`. The complete exact numerator is retained in `MAX_SPLIT_DEVIATION_NUMERATOR.txt`. This is measured independently rather than assuming the design's aggregate bound.

## Runtime certificate and integer bounds

- Maximum width: 642 at `F=25882479728004339, w=1175179852692074280, W=1175656547196813419`
- Required bound: `<= 16777216`
- Width bit-length histogram: `{8: 54668, 9: 116589, 10: 42555}`
- No scratch/endpoint bound errors, panics, or thresholds wider than 512 bits.

## Invalid domain

Rejected `F=0`, `F>2^63`, `w=0`, `W=0`, and `w>W`; accepted all legal endpoints tested.

## Result

PASS. No mismatch, invariant violation, certificate failure, or unexpected production error was observed.

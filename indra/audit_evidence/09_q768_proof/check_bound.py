#!/usr/bin/env python3
"""Exact-integer checker for the bounds derived in Q768_ERROR_BOUND_PROOF.md."""

from math import factorial

S = 1 << 768


def ceil_div(n: int, d: int) -> int:
    assert n >= 0 and d > 0
    return (n + d - 1) // d


def mul_bound(a_hi: int, b_hi: int, wa: int, wb: int) -> tuple[int, int]:
    """Upper endpoint and universal integer width bound for production mul."""
    out_hi = ceil_div(a_hi * b_hi, S)
    # ceil(H/S)-floor(L/S) < (H-L)/S+2.  This integer form is conservative.
    out_width = ceil_div(b_hi * wa + a_hi * wb, S) + 1
    return out_hi, out_width


def div_scalar_bound(a_hi: int, wa: int, d: int) -> tuple[int, int]:
    """Upper endpoint and universal width bound for production divi."""
    return ceil_div(a_hi, d), ceil_div(wa, d) + 1


def stake_endpoints(l_lo: int, l_hi: int, w: int, total: int) -> tuple[int, int]:
    """Instantiate the algebraic stake-endpoint lemma with exact integers.

    These assertions check concrete inputs used by this supporting artifact;
    they do not prove the universally quantified lemma.  Its proof is the
    order argument in Section 5 of Q768_ERROR_BOUND_PROOF.md.
    """
    assert 0 <= l_lo <= l_hi
    assert 1 <= w <= total
    z_lo = (l_lo * w) // total
    z_hi = ceil_div(l_hi * w, total)
    # Algebraic premise: l_hi*w <= l_hi*total, hence ceil(...) <= l_hi.
    assert l_hi * w <= l_hi * total
    assert z_hi <= l_hi
    assert 0 <= z_lo <= z_hi
    return z_lo, z_hi


def main() -> None:
    # F<=2^63 gives y<=1/3.  Since S=1 mod 3, ceil(S/3)=(S+2)/3.
    y_hi, y_width = ceil_div(S, 3), 1
    assert 3 * y_hi == S + 2
    y2_hi, y2_width = mul_bound(y_hi, y_hi, y_width, y_width)
    assert y2_hi < S

    p_hi, p_width = y_hi, y_width
    sum_hi = 0
    sum_width = 0
    for n in range(256):
        term_hi, term_width = div_scalar_bound(p_hi, p_width, 2 * n + 1)
        sum_hi += term_hi
        sum_width += term_width
        if n != 255:
            p_hi, p_width = mul_bound(p_hi, y2_hi, p_width, y2_width)

    # At loop exit p encloses y^511; the next multiplication encloses y^513.
    y513_hi, _ = mul_bound(p_hi, y2_hi, p_width, y2_width)
    log_tail = ceil_div(2 * y513_hi * S, 513 * (S - y2_hi))
    log_hi = 2 * sum_hi + log_tail
    log_width = 2 * sum_width + log_tail

    assert sum_width == 512
    assert log_tail == 1
    assert log_width == 1025
    # Exact rational proof that every production z_hi is below 7/10.
    assert 10 * log_hi < 7 * S

    # Exact supporting instances for the integer endpoint and width lemmas.
    # Universality comes from the algebraic proof, not this finite exercise.
    log_lo_for_bound = log_hi - log_width
    assert log_lo_for_bound >= 0
    for total in (1, 200, (1 << 64) - 1):
        for w in sorted({1, total, max(1, total - 1)}):
            z_lo, z_hi = stake_endpoints(
                log_lo_for_bound, log_hi, w, total
            )
            assert z_hi <= log_hi
            assert z_hi - z_lo <= log_width + 1

    phi_rounding = {}
    for terms in (128, 129):
        term_hi, term_width = log_hi, 0
        accumulated_width = 0
        for k in range(1, terms + 1):
            if k > 1:
                term_hi, term_width = mul_bound(
                    term_hi, log_hi, term_width, 0
                )
                term_hi, term_width = div_scalar_bound(term_hi, term_width, k)
            accumulated_width += term_width
        phi_rounding[terms] = accumulated_width

    assert phi_rounding[128] == 254
    assert phi_rounding[129] == 256

    # ln(2)<7/10 follows because the first four positive exp(7/10) terms exceed 2:
    # 1 + 7/10 + (7/10)^2/2 + (7/10)^3/6 = 12013/6000 > 2.
    assert 12013 > 2 * 6000
    # Exact bounds for the two alternating-series remainders in scaled units.
    assert S * 7**129 < 10**129 * factorial(129)
    assert S * 7**130 < 10**130 * factorial(130)

    # True-z uncertainty is separate from both point-polynomial evaluations.
    z_uncertainty = log_width + 1
    lower_point_rounding = phi_rounding[128]
    upper_point_rounding = phi_rounding[129]
    # Both omitted tails are strictly below one Q768 unit.
    phi_width_strict = (
        upper_point_rounding + 1 + z_uncertainty + 1 + lower_point_rounding
    )
    phi_integer_bound = phi_width_strict - 1
    assert phi_width_strict == 1538
    assert phi_integer_bound == 1537
    assert phi_integer_bound < 1 << 24

    # Only the lower-side error matters for conservative threshold loss.
    lower_error_strict = z_uncertainty + 1 + lower_point_rounding
    assert lower_error_strict == 1281
    assert lower_error_strict < 1 << 24
    assert lower_error_strict < 1 << 11

    # Scratch and endpoint bounds from the proven operand ranges.
    assert (S * S).bit_length() <= 1537 < 2048
    assert S.bit_length() == 769 < 1024

    print(f"S bits: {S.bit_length()}")
    print(f"y2 width bound: {y2_width}")
    print(f"log term-width sum: {sum_width}")
    print(f"log analytic tail: {log_tail}")
    print(f"log interval width bound: {log_width}")
    print(f"128-term rounding-width sum: {phi_rounding[128]}")
    print(f"129-term rounding-width sum: {phi_rounding[129]}")
    print(f"true-z uncertainty bound: {z_uncertainty}")
    print(f"phi interval integer bound: {phi_integer_bound}")
    print(f"lower error: < {lower_error_strict} / 2^768 < 2^-757")
    print("stake endpoint instances: hold (universal result is algebraic)")
    print("classification support: all exact finite inequalities hold")


if __name__ == "__main__":
    main()

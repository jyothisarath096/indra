From Stdlib Require Import Reals Lra ZArith Lia.

Open Scope R_scope.

Section AbstractComposition.

Variables z_lo z_true z_hi : R.
Variables poly_lo p128 p129 poly_hi : R.
Variable g : R -> R.

Hypothesis z_order : z_lo <= z_true <= z_hi.
Hypothesis g_monotone : forall x y, x <= y -> g x <= g y.
Hypothesis lower_rounding_order : poly_lo <= p128.
Hypothesis lower_series_order : p128 <= g z_lo.
Hypothesis upper_series_order : g z_hi <= p129.
Hypothesis upper_rounding_order : p129 <= poly_hi.

Theorem abstract_certificate_brackets_true_value :
  poly_lo <= g z_true <= poly_hi.
Proof.
  split.
  - eapply Rle_trans; [exact lower_rounding_order|].
    eapply Rle_trans; [exact lower_series_order|].
    apply g_monotone. exact (proj1 z_order).
  - eapply Rle_trans; [|exact upper_rounding_order].
    eapply Rle_trans; [|exact upper_series_order].
    apply g_monotone. exact (proj2 z_order).
Qed.

Hypothesis upper_rounding_error : 0 <= poly_hi - p129 <= 256.
Hypothesis upper_series_error : 0 <= p129 - g z_hi < 1.
Hypothesis propagated_input_error : 0 <= g z_hi - g z_lo <= 1026.
Hypothesis lower_series_error : 0 <= g z_lo - p128 < 1.
Hypothesis lower_rounding_error : 0 <= p128 - poly_lo <= 254.

Theorem composed_real_width_is_strictly_below_1538 :
  poly_hi - poly_lo < 1538.
Proof. lra. Qed.

Hypothesis true_from_lower_input : 0 <= g z_true - g z_lo <= 1026.

Theorem composed_lower_error_is_strictly_below_1281 :
  g z_true - poly_lo < 1281.
Proof. lra. Qed.

End AbstractComposition.

Open Scope Z_scope.

Theorem integer_width_sharpening (width : Z) :
  (IZR width < 1538)%R -> width <= 1537.
Proof.
  intro H.
  assert (width < 1538) by
    (apply lt_IZR; change (IZR width < IZR 1538)%R; exact H).
  lia.
Qed.

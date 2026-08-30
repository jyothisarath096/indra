From Stdlib Require Import Reals.

Open Scope R_scope.

Fixpoint factorial_R (n : nat) : R :=
  match n with
  | O => 1
  | S n' => INR (S n') * factorial_R n'
  end.

Fixpoint log_partial (terms : nat) (y : R) : R :=
  match terms with
  | O => 0
  | S n =>
      log_partial n y + 2 * y ^ (2 * n + 1) / INR (2 * n + 1)
  end.

Fixpoint phi_partial (terms : nat) (x : R) : R :=
  match terms with
  | O => 0
  | S n =>
      let k := S n in
      let magnitude := x ^ k / factorial_R k in
      phi_partial n x + if Nat.even k then -magnitude else magnitude
  end.

Definition true_log_from_y (y : R) : R := ln ((1 + y) / (1 - y)).
Definition true_phi (x : R) : R := 1 - exp (-x).

(* First unclosed analytic obligation: the exact 256-term production series. *)
Theorem log_tail_after_exactly_256_terms :
  forall y : R,
    0 < y <= 1 / 3 ->
    log_partial 256%nat y <= true_log_from_y y /\
    true_log_from_y y - log_partial 256%nat y
      <= 2 * y ^ 513 / (513 * (1 - y ^ 2)).
Proof.
  intros y Hy.
  (* Requires a formal power-series theorem for atanh/log and a geometric-tail
     argument. Gappa has no transcendental-series rule for this step. *)
Abort.

(* Second unclosed analytic obligation: the exact 128/129 production sums. *)
Theorem phi_bracket_at_exactly_128_and_129_terms :
  forall x : R,
    0 <= x < 7 / 10 ->
    phi_partial 128%nat x <= true_phi x <= phi_partial 129%nat x /\
    true_phi x - phi_partial 128%nat x
      < x ^ 129 / factorial_R 129%nat /\
    phi_partial 129%nat x - true_phi x
      < x ^ 130 / factorial_R 130%nat.
Proof.
  intros x Hx.
  (* Requires a formal alternating-series remainder theorem for exp, including
     monotone terms on x < 7/10. Gappa cannot create this induction. *)
Abort.

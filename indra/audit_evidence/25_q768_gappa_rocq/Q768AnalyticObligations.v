From Stdlib Require Import Reals Arith.Factorial Psatz.
From Coquelicot Require Import Derive ElemFct.

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

Lemma factorial_R_eq_INR_fact :
  forall n : nat, factorial_R n = INR (fact n).
Proof.
  induction n as [|n IH].
  - reflexivity.
  - change (INR (S n) * factorial_R n = INR (S n * fact n)).
    rewrite IH, mult_INR. reflexivity.
Qed.

Lemma ex_derive_n_exp_all :
  forall (n : nat) (x : R), ex_derive_n exp n x.
Proof.
  intros [|n] x.
  - exact I.
  - simpl. exists (exp x). exact (is_derive_n_exp (S n) x).
Qed.

Lemma is_derive_n_exp_neg :
  forall (n : nat) (x : R),
    is_derive_n (fun t : R => exp (-t)) n x ((-1) ^ n * exp (-x)).
Proof.
  intros n x.
  apply is_derive_n_comp_opp.
  - apply Hierarchy.filter_forall. intros y k Hk.
    apply ex_derive_n_exp_all.
  - apply is_derive_n_exp.
Qed.

Lemma Derive_n_exp_neg :
  forall (n : nat) (x : R),
    Derive_n (fun t : R => exp (-t)) n x = (-1) ^ n * exp (-x).
Proof.
  intros n x. apply is_derive_n_unique, is_derive_n_exp_neg.
Qed.

Definition exp_neg_taylor (terms : nat) (x : R) : R :=
  sum_f_R0
    (fun k : nat => x ^ k / INR (fact k) * (-1) ^ k)
    terms.

Lemma alternating_sign_from_even :
  forall (k : nat) (a : R),
    (if Nat.even k then -a else a) = -(a * (-1) ^ k).
Proof.
  intros k a.
  destruct (even_odd_cor k) as [p [Hk | Hk]]; subst k.
  - rewrite Nat.even_mul, Nat.even_2, pow_1_even. simpl. ring.
  - rewrite Nat.even_succ, Nat.odd_mul, Nat.odd_2, pow_1_odd. simpl. ring.
Qed.

Lemma phi_partial_as_taylor :
  forall (terms : nat) (x : R),
    phi_partial terms x = 1 - exp_neg_taylor terms x.
Proof.
  intros terms x. induction terms as [|n IH].
  - unfold exp_neg_taylor. simpl. field.
  - cbn [phi_partial].
    rewrite IH, alternating_sign_from_even, factorial_R_eq_INR_fact.
    unfold exp_neg_taylor. rewrite tech5. ring.
Qed.

Lemma exp_neg_taylor_lagrange :
  forall (terms : nat) (x : R),
    0 < x ->
    exists zeta : R,
      0 < zeta < x /\
      exp (-x) =
        exp_neg_taylor terms x +
        x ^ (S terms) / INR (fact (S terms)) *
          ((-1) ^ (S terms) * exp (-zeta)).
Proof.
  intros terms x Hx.
  assert (Hsmooth :
    forall t : R,
      0 <= t <= x ->
      forall k : nat,
        (k <= S terms)%nat ->
        ex_derive_n (fun u : R => exp (-u)) k t).
  {
    intros t Ht [|k] Hk.
    - exact I.
    - simpl. exists ((-1) ^ (S k) * exp (-t)).
      exact (is_derive_n_exp_neg (S k) t).
  }
  destruct
    (Taylor_Lagrange (fun u : R => exp (-u)) terms 0 x Hx Hsmooth)
    as [zeta [Hzeta Heq]].
  exists zeta. split; [exact Hzeta |].
  replace (x - 0) with x in Heq by ring.
  assert (Hsum :
    sum_f_R0
      (fun m : nat => x ^ m / INR (fact m) *
        Derive_n (fun u : R => exp (-u)) m 0)
      terms = exp_neg_taylor terms x).
  {
    unfold exp_neg_taylor. apply sum_eq. intros m Hm.
    rewrite Derive_n_exp_neg, Ropp_0, exp_0. ring.
  }
  rewrite Hsum, Derive_n_exp_neg in Heq.
  exact Heq.
Qed.

Lemma exp_neg_between_zero_and_one :
  forall z : R, 0 < z -> 0 < exp (-z) < 1.
Proof.
  intros z Hz. split.
  - apply exp_pos.
  - rewrite <- exp_0. apply exp_increasing. lra.
Qed.

Lemma positive_lagrange_factor_is_strictly_smaller :
  forall (n : nat) (x z : R),
    0 < x -> 0 < z ->
    0 < x ^ n / INR (fact n) * exp (-z) <
      x ^ n / INR (fact n).
Proof.
  intros n x z Hx Hz.
  assert (Hcoefficient : 0 < x ^ n / INR (fact n)).
  {
    apply Rdiv_lt_0_compat.
    - apply pow_lt. exact Hx.
    - apply INR_fact_lt_0.
  }
  destruct (exp_neg_between_zero_and_one z Hz) as [Hexp_pos Hexp_lt].
  nra.
Qed.

Lemma phi_partial_at_zero :
  forall terms : nat, phi_partial terms 0 = 0.
Proof.
  induction terms as [|n IH].
  - reflexivity.
  - change
      ((phi_partial n 0 +
       (if Nat.even (S n)
        then -(0 ^ (S n) / factorial_R (S n))
        else 0 ^ (S n) / factorial_R (S n))) = 0).
    rewrite (pow_i (S n) (Nat.lt_0_succ n)), IH.
    destruct (Nat.even (S n)); unfold Rdiv; ring.
Qed.

Lemma phi_at_zero_is_exact :
  true_phi 0 = 0 /\
  phi_partial 128%nat 0 = 0 /\
  phi_partial 129%nat 0 = 0.
Proof.
  split.
  - unfold true_phi. rewrite Ropp_0, exp_0. ring.
  - split; apply phi_partial_at_zero.
Qed.

Fixpoint even_geom_partial (terms : nat) (x : R) : R :=
  match terms with
  | O => 0
  | S n => even_geom_partial n x + x ^ (2 * n)
  end.

Lemma even_geom_partial_finite_identity :
  forall (terms : nat) (x : R),
    (1 - x ^ 2) * even_geom_partial terms x = 1 - x ^ (2 * terms).
Proof.
  intros terms x. induction terms as [|n IH].
  - simpl. ring.
  - cbn [even_geom_partial].
    rewrite Rmult_plus_distr_l, IH.
    replace (2 * S n)%nat with (2 * n + 2)%nat by lia.
    rewrite pow_add. simpl. ring.
Qed.

Lemma log_partial_at_zero :
  forall terms : nat, log_partial terms 0 = 0.
Proof.
  induction terms as [|n IH].
  - reflexivity.
  - cbn [log_partial]. rewrite IH, (pow_i (2 * n + 1)).
    + unfold Rdiv. ring.
    + lia.
Qed.

Lemma is_derive_log_series_term :
  forall (n : nat) (x : R),
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => 2 * t ^ (2 * n + 1) / INR (2 * n + 1))
      x (2 * x ^ (2 * n)).
Proof.
  intros n x.
  eapply (@is_derive_ext
    Hierarchy.R_AbsRing Hierarchy.R_NormedModule
    (fun t : R => (2 / INR (2 * n + 1)) * t ^ (2 * n + 1))
    (fun t : R => 2 * t ^ (2 * n + 1) / INR (2 * n + 1))
    x (2 * x ^ (2 * n))).
  - intros t. unfold Rdiv.
    change
      ((2 : R) * / INR (2 * n + 1) * t ^ (2 * n + 1) =
       2 * t ^ (2 * n + 1) * / INR (2 * n + 1)).
    ring.
  - replace (2 * x ^ (2 * n)) with
      ((2 / INR (2 * n + 1)) *
       (INR (2 * n + 1) * 1 * x ^ pred (2 * n + 1))).
    + apply is_derive_scal, is_derive_pow.
      exact (@is_derive_id Hierarchy.R_AbsRing x).
    + replace (pred (2 * n + 1)) with (2 * n)%nat by lia.
      field. apply not_0_INR. lia.
Qed.

Lemma is_derive_log_partial :
  forall (terms : nat) (x : R),
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => log_partial terms t) x
      (2 * even_geom_partial terms x).
Proof.
  intros terms x. induction terms as [|n IH].
  - cbn [log_partial even_geom_partial].
    replace (2 * 0) with 0 by ring.
    exact (@is_derive_const
      Hierarchy.R_AbsRing Hierarchy.R_NormedModule 0 x).
  - cbn [log_partial even_geom_partial].
    replace (2 * (even_geom_partial n x + x ^ (2 * n))) with
      (2 * even_geom_partial n x + 2 * x ^ (2 * n)) by ring.
    apply (@is_derive_plus
      Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => log_partial n t)
      (fun t : R => 2 * t ^ (2 * n + 1) / INR (2 * n + 1))
      x (2 * even_geom_partial n x) (2 * x ^ (2 * n))).
    + exact IH.
    + apply is_derive_log_series_term.
Qed.

Lemma is_derive_true_log_from_y :
  forall x : R,
    -1 < x < 1 ->
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      true_log_from_y x (2 / (1 - x ^ 2)).
Proof.
  intros x Hx.
  assert (Hnum :
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => 1 + t) x 1).
  {
    assert (Hraw :
      @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun t : R => 1 + t) x (0 + 1)).
    {
      apply (@is_derive_plus
        Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun _ : R => 1) (fun t : R => t) x 0 1).
      - exact (@is_derive_const
          Hierarchy.R_AbsRing Hierarchy.R_NormedModule 1 x).
      - exact (@is_derive_id Hierarchy.R_AbsRing x).
    }
    replace (0 + 1) with 1 in Hraw by ring. exact Hraw.
  }
  assert (Hden :
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => 1 - t) x (-1)).
  {
    assert (Hraw :
      @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun t : R => 1 - t) x (0 - 1)).
    {
      apply (@is_derive_minus
        Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun _ : R => 1) (fun t : R => t) x 0 1).
      - exact (@is_derive_const
          Hierarchy.R_AbsRing Hierarchy.R_NormedModule 1 x).
      - exact (@is_derive_id Hierarchy.R_AbsRing x).
    }
    replace (0 - 1) with (-1) in Hraw by ring. exact Hraw.
  }
  assert (Hden_nonzero : 1 - x <> 0) by lra.
  assert (Hquot :
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => (1 + t) / (1 - t)) x
      ((1 * (1 - x) - (1 + x) * (-1)) / (1 - x) ^ 2)).
  {
    apply is_derive_div; assumption.
  }
  assert (Hquot_pos : 0 < (1 + x) / (1 - x)).
  {
    apply Rdiv_lt_0_compat; lra.
  }
  assert (Hcomp := @is_derive_comp
    Hierarchy.R_AbsRing Hierarchy.R_NormedModule
    ln (fun t : R => (1 + t) / (1 - t)) x
    (/ ((1 + x) / (1 - x)))
    ((1 * (1 - x) - (1 + x) * (-1)) / (1 - x) ^ 2)
    (is_derive_ln _ Hquot_pos) Hquot).
  unfold true_log_from_y.
  replace (2 / (1 - x ^ 2)) with
    (((1 * (1 - x) - (1 + x) * (-1)) / (1 - x) ^ 2) *
     / ((1 + x) / (1 - x))).
  - exact Hcomp.
  - field; nra.
Qed.

Lemma log_y_substitution_identity :
  forall f : R,
    0 <= f < 1 ->
    true_log_from_y (f / (2 - f)) = - ln (1 - f).
Proof.
  intros f Hf. unfold true_log_from_y.
  replace
    ((1 + f / (2 - f)) / (1 - f / (2 - f)))
    with (/ (1 - f)).
  - apply ln_Rinv. lra.
  - field; lra.
Qed.

Definition log_remainder (terms : nat) (x : R) : R :=
  true_log_from_y x - log_partial terms x.

Lemma log_remainder_at_zero :
  forall terms : nat, log_remainder terms 0 = 0.
Proof.
  intros terms. unfold log_remainder, true_log_from_y.
  rewrite log_partial_at_zero. replace ((1 + 0) / (1 - 0)) with 1 by field.
  rewrite ln_1. ring.
Qed.

Lemma is_derive_log_remainder :
  forall (terms : nat) (x : R),
    -1 < x < 1 ->
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => log_remainder terms t) x
      (2 * x ^ (2 * terms) / (1 - x ^ 2)).
Proof.
  intros terms x Hx.
  assert (Hraw := @is_derive_minus
    Hierarchy.R_AbsRing Hierarchy.R_NormedModule
    true_log_from_y (fun t : R => log_partial terms t) x
    (2 / (1 - x ^ 2)) (2 * even_geom_partial terms x)
    (is_derive_true_log_from_y x Hx)
    (is_derive_log_partial terms x)).
  unfold log_remainder.
  replace (2 * x ^ (2 * terms) / (1 - x ^ 2)) with
    (2 / (1 - x ^ 2) - 2 * even_geom_partial terms x).
  - exact Hraw.
  - assert (Hden : 1 - x ^ 2 <> 0) by nra.
    pose proof (even_geom_partial_finite_identity terms x) as Hgeom.
    apply Rmult_eq_reg_r with (r := 1 - x ^ 2); [|exact Hden].
    unfold Rdiv.
    rewrite Rmult_minus_distr_r.
    repeat rewrite Rmult_assoc.
    rewrite (Rinv_l _ Hden).
    nra.
Qed.

Definition log_tail_bound (terms : nat) (x : R) : R :=
  2 * x ^ (2 * terms + 1) /
    (INR (2 * terms + 1) * (1 - x ^ 2)).

Lemma log_tail_bound_at_zero :
  forall terms : nat, log_tail_bound terms 0 = 0.
Proof.
  intros terms. unfold log_tail_bound.
  rewrite (pow_i (2 * terms + 1)); [unfold Rdiv; ring | lia].
Qed.

Lemma is_derive_log_tail_bound :
  forall (terms : nat) (x : R),
    -1 < x < 1 ->
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => log_tail_bound terms t) x
      (2 * x ^ (2 * terms) / (1 - x ^ 2) +
       4 * x ^ (2 * terms + 2) /
         (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2)).
Proof.
  intros terms x Hx.
  assert (Hsquare :
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => t ^ 2) x (2 * x)).
  {
    replace (2 * x) with (INR 2 * 1 * x ^ pred 2) by (simpl; ring).
    apply is_derive_pow. exact (@is_derive_id Hierarchy.R_AbsRing x).
  }
  assert (Hden :
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => 1 - t ^ 2) x (-2 * x)).
  {
    assert (Hraw :
      @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun t : R => 1 - t ^ 2) x (0 - 2 * x)).
    {
      apply (@is_derive_minus
        Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun _ : R => 1) (fun t : R => t ^ 2) x 0 (2 * x)).
      - exact (@is_derive_const
          Hierarchy.R_AbsRing Hierarchy.R_NormedModule 1 x).
      - exact Hsquare.
    }
    replace (0 - 2 * x) with (-2 * x) in Hraw by ring. exact Hraw.
  }
  assert (Hden_nonzero : 1 - x ^ 2 <> 0) by nra.
  assert (Hraw := is_derive_div
    _ _ x _ _
    (is_derive_log_series_term terms x) Hden Hden_nonzero).
  assert (Hindex : INR (2 * terms + 1) <> 0).
  { apply not_0_INR. lia. }
  unfold log_tail_bound.
  replace
    (2 * x ^ (2 * terms) / (1 - x ^ 2) +
     4 * x ^ (2 * terms + 2) /
       (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2))
    with
    (((2 * x ^ (2 * terms)) * (1 - x ^ 2) -
      (2 * x ^ (2 * terms + 1) / INR (2 * terms + 1)) * (-2 * x)) /
     (1 - x ^ 2) ^ 2).
  - eapply (@is_derive_ext
      Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R =>
        (2 * t ^ (2 * terms + 1) / INR (2 * terms + 1)) /
          (1 - t ^ 2))
      (fun t : R =>
        2 * t ^ (2 * terms + 1) /
          (INR (2 * terms + 1) * (1 - t ^ 2)))
      x
      (((2 * x ^ (2 * terms)) * (1 - x ^ 2) -
        (2 * x ^ (2 * terms + 1) / INR (2 * terms + 1)) * (-2 * x)) /
       (1 - x ^ 2) ^ 2)).
    + intros t. unfold Rdiv.
      change
        ((2 : R) * t ^ (2 * terms + 1) * / INR (2 * terms + 1) *
          / (1 - t ^ 2) =
         2 * t ^ (2 * terms + 1) *
          / (INR (2 * terms + 1) * (1 - t ^ 2))).
      rewrite Rinv_mult. ring.
    + exact Hraw.
  - change
      (((2 : R) * x ^ (2 * terms) * (1 - x ^ 2) -
        2 * x ^ (2 * terms + 1) / INR (2 * terms + 1) * (-2 * x)) /
       (1 - x ^ 2) ^ 2 =
       2 * x ^ (2 * terms) / (1 - x ^ 2) +
       4 * x ^ (2 * terms + 2) /
         (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2)).
    assert (Hinv_den :
      / (1 - x ^ 2) =
        (1 - x ^ 2) * / ((1 - x ^ 2) ^ 2)).
    {
      replace ((1 - x ^ 2) ^ 2) with
        ((1 - x ^ 2) * (1 - x ^ 2)) by (simpl; ring).
      rewrite Rinv_mult.
      rewrite <- Rmult_assoc, (Rinv_r _ Hden_nonzero).
      ring.
    }
    unfold Rdiv.
    rewrite (Rinv_mult (INR (2 * terms + 1)) ((1 - x ^ 2) ^ 2)).
    rewrite Hinv_den.
    replace (2 * terms + 2)%nat with ((2 * terms + 1) + 1)%nat by lia.
    rewrite pow_add. simpl.
    change
      ((((2 : R) * x ^ (terms + (terms + 0)) * (1 - x * (x * 1)) -
         2 * (x ^ (terms + (terms + 0)) * (x * 1)) *
           / INR (terms + (terms + 0) + 1) * (-2 * x)) *
        / ((1 - x * (x * 1)) * ((1 - x * (x * 1)) * 1))) =
       2 * x ^ (terms + (terms + 0)) *
         ((1 - x * (x * 1)) *
          / ((1 - x * (x * 1)) * ((1 - x * (x * 1)) * 1))) +
       4 * x ^ (terms + (terms + 0) + 1 + 1) *
         (/ INR (terms + (terms + 0) + 1) *
          / ((1 - x * (x * 1)) * ((1 - x * (x * 1)) * 1)))).
    replace (x ^ (terms + (terms + 0) + 1 + 1)) with
      (x ^ (terms + (terms + 0)) * x * x).
    + ring.
    + repeat rewrite pow_add. simpl. ring.
Qed.

Definition log_tail_gap (terms : nat) (x : R) : R :=
  log_tail_bound terms x - log_remainder terms x.

Lemma log_tail_gap_at_zero :
  forall terms : nat, log_tail_gap terms 0 = 0.
Proof.
  intros terms. unfold log_tail_gap.
  rewrite log_tail_bound_at_zero, log_remainder_at_zero. ring.
Qed.

Lemma is_derive_log_tail_gap :
  forall (terms : nat) (x : R),
    -1 < x < 1 ->
    @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
      (fun t : R => log_tail_gap terms t) x
      (4 * x ^ (2 * terms + 2) /
        (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2)).
Proof.
  intros terms x Hx.
  assert (Hraw := @is_derive_minus
    Hierarchy.R_AbsRing Hierarchy.R_NormedModule
    (fun t : R => log_tail_bound terms t)
    (fun t : R => log_remainder terms t) x
    (2 * x ^ (2 * terms) / (1 - x ^ 2) +
     4 * x ^ (2 * terms + 2) /
       (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2))
    (2 * x ^ (2 * terms) / (1 - x ^ 2))
    (is_derive_log_tail_bound terms x Hx)
    (is_derive_log_remainder terms x Hx)).
  unfold log_tail_gap.
  replace
    (4 * x ^ (2 * terms + 2) /
      (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2))
    with
    ((2 * x ^ (2 * terms) / (1 - x ^ 2) +
      4 * x ^ (2 * terms + 2) /
        (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2)) -
     2 * x ^ (2 * terms) / (1 - x ^ 2)) by ring.
  exact Hraw.
Qed.

Lemma even_power_nonnegative :
  forall (x : R) (n : nat), 0 <= x ^ (2 * n).
Proof.
  intros x n. replace (2 * n)%nat with (n * 2)%nat by lia.
  rewrite pow_mult. apply pow2_ge_0.
Qed.

Lemma log_remainder_derivative_nonnegative :
  forall (terms : nat) (x : R),
    0 <= x < 1 ->
    0 <= 2 * x ^ (2 * terms) / (1 - x ^ 2).
Proof.
  intros terms x Hx. unfold Rdiv.
  apply Rmult_le_pos.
  - apply Rmult_le_pos; [lra | apply even_power_nonnegative].
  - apply Rlt_le, Rinv_0_lt_compat. nra.
Qed.

Lemma log_tail_gap_derivative_nonnegative :
  forall (terms : nat) (x : R),
    0 <= x < 1 ->
    0 <= 4 * x ^ (2 * terms + 2) /
      (INR (2 * terms + 1) * (1 - x ^ 2) ^ 2).
Proof.
  intros terms x Hx. unfold Rdiv.
  apply Rmult_le_pos.
  - apply Rmult_le_pos; [lra |].
    replace (2 * terms + 2)%nat with (2 * (terms + 1))%nat by lia.
    apply even_power_nonnegative.
  - apply Rlt_le, Rinv_0_lt_compat.
    apply Rmult_lt_0_compat.
    + apply lt_0_INR. lia.
    + apply pow_lt. nra.
Qed.

Lemma log_remainder_nonnegative :
  forall (terms : nat) (y : R),
    0 <= y < 1 -> 0 <= log_remainder terms y.
Proof.
  intros terms y Hy.
  destruct (Req_dec y 0) as [Hy_zero | Hy_nonzero].
  - subst y. rewrite log_remainder_at_zero. lra.
  - assert (Hy_pos : 0 < y) by lra.
    pose proof
      (MVT_gen
        (fun t : R => log_remainder terms t) 0 y
        (fun t : R => 2 * t ^ (2 * terms) / (1 - t ^ 2)))
      as Hmvt.
    rewrite (Rmin_left 0 y), (Rmax_right 0 y) in Hmvt by lra.
    assert (Hder : forall z : R, 0 < z < y ->
      @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun t : R => log_remainder terms t) z
        (2 * z ^ (2 * terms) / (1 - z ^ 2))).
    {
      intros z Hz. apply is_derive_log_remainder. lra.
    }
    specialize (Hmvt Hder).
    assert (Hcont : forall z : R, 0 <= z <= y ->
      continuity_pt (fun t : R => log_remainder terms t) z).
    {
      intros z Hz. apply derivable_continuous_pt.
      exists (2 * z ^ (2 * terms) / (1 - z ^ 2)).
      apply is_derive_Reals, is_derive_log_remainder. lra.
    }
    specialize (Hmvt Hcont).
    destruct Hmvt as [c [Hc Heq]].
    rewrite log_remainder_at_zero in Heq.
    replace (y - 0) with y in Heq by ring.
    pose proof (log_remainder_derivative_nonnegative terms c) as Hnonneg.
    assert (Hcy : 0 <= c < 1) by lra.
    specialize (Hnonneg Hcy).
    nra.
Qed.

Lemma log_tail_gap_nonnegative :
  forall (terms : nat) (y : R),
    0 <= y < 1 -> 0 <= log_tail_gap terms y.
Proof.
  intros terms y Hy.
  destruct (Req_dec y 0) as [Hy_zero | Hy_nonzero].
  - subst y. rewrite log_tail_gap_at_zero. lra.
  - assert (Hy_pos : 0 < y) by lra.
    pose proof
      (MVT_gen
        (fun t : R => log_tail_gap terms t) 0 y
        (fun t : R =>
          4 * t ^ (2 * terms + 2) /
            (INR (2 * terms + 1) * (1 - t ^ 2) ^ 2)))
      as Hmvt.
    rewrite (Rmin_left 0 y), (Rmax_right 0 y) in Hmvt by lra.
    assert (Hder : forall z : R, 0 < z < y ->
      @is_derive Hierarchy.R_AbsRing Hierarchy.R_NormedModule
        (fun t : R => log_tail_gap terms t) z
        (4 * z ^ (2 * terms + 2) /
          (INR (2 * terms + 1) * (1 - z ^ 2) ^ 2))).
    {
      intros z Hz. apply is_derive_log_tail_gap. lra.
    }
    specialize (Hmvt Hder).
    assert (Hcont : forall z : R, 0 <= z <= y ->
      continuity_pt (fun t : R => log_tail_gap terms t) z).
    {
      intros z Hz. apply derivable_continuous_pt.
      exists (4 * z ^ (2 * terms + 2) /
        (INR (2 * terms + 1) * (1 - z ^ 2) ^ 2)).
      apply is_derive_Reals, is_derive_log_tail_gap. lra.
    }
    specialize (Hmvt Hcont).
    destruct Hmvt as [c [Hc Heq]].
    rewrite log_tail_gap_at_zero in Heq.
    replace (y - 0) with y in Heq by ring.
    pose proof (log_tail_gap_derivative_nonnegative terms c) as Hnonneg.
    assert (Hcy : 0 <= c < 1) by lra.
    specialize (Hnonneg Hcy).
    nra.
Qed.

(* Closed analytic obligation: the exact 256-term production series. *)
Theorem log_tail_after_exactly_256_terms :
  forall y : R,
    0 < y <= 1 / 3 ->
    log_partial 256%nat y <= true_log_from_y y /\
    true_log_from_y y - log_partial 256%nat y
      <= 2 * y ^ 513 / (513 * (1 - y ^ 2)).
Proof.
  intros y Hy.
  assert (Hdomain : 0 <= y < 1) by lra.
  pose proof (log_remainder_nonnegative 256%nat y Hdomain) as Hremainder.
  pose proof (log_tail_gap_nonnegative 256%nat y Hdomain) as Hgap.
  split.
  - unfold log_remainder in Hremainder. lra.
  - unfold log_tail_gap, log_tail_bound, log_remainder in Hgap.
    change
      (0 <= 2 * y ^ 513 / (INR 513 * (1 - y ^ 2)) -
        (true_log_from_y y - log_partial 256%nat y))
      in Hgap.
    assert (H513 : INR 513 = 513) by (simpl; ring).
    rewrite H513 in Hgap.
    lra.
Qed.

(* Closed analytic obligation: the exact 128/129 production sums. *)
Theorem phi_bracket_at_exactly_128_and_129_terms :
  forall x : R,
    0 < x < 7 / 10 ->
    phi_partial 128%nat x <= true_phi x <= phi_partial 129%nat x /\
    true_phi x - phi_partial 128%nat x
      < x ^ 129 / factorial_R 129%nat /\
    phi_partial 129%nat x - true_phi x
      < x ^ 130 / factorial_R 130%nat.
Proof.
  intros x Hx.
  destruct Hx as [Hx_pos _Hx_upper].
  destruct (exp_neg_taylor_lagrange 128%nat x Hx_pos)
    as [zeta128 [Hzeta128 Htaylor128]].
  destruct (exp_neg_taylor_lagrange 129%nat x Hx_pos)
    as [zeta129 [Hzeta129 Htaylor129]].

  change (S 128)%nat with 129%nat in Htaylor128.
  change (S 129)%nat with 130%nat in Htaylor129.
  replace 129%nat with (S (2 * 64))%nat in Htaylor128 by reflexivity.
  replace 130%nat with (2 * 65)%nat in Htaylor129 by reflexivity.
  rewrite pow_1_odd in Htaylor128.
  rewrite pow_1_even in Htaylor129.
  change
    (exp (-x) = exp_neg_taylor 128%nat x +
      x ^ 129 / INR (fact 129%nat) * (-1 * exp (-zeta128)))
    in Htaylor128.
  change
    (exp (-x) = exp_neg_taylor 129%nat x +
      x ^ 130 / INR (fact 130%nat) * (1 * exp (-zeta129)))
    in Htaylor129.

  assert (Herror128 :
    true_phi x - phi_partial 128%nat x =
      x ^ 129 / INR (fact 129%nat) * exp (-zeta128)).
  {
    unfold true_phi. rewrite phi_partial_as_taylor.
    nra.
  }
  assert (Herror129 :
    phi_partial 129%nat x - true_phi x =
      x ^ 130 / INR (fact 130%nat) * exp (-zeta129)).
  {
    unfold true_phi. rewrite phi_partial_as_taylor.
    nra.
  }

  destruct
    (positive_lagrange_factor_is_strictly_smaller
      129%nat x zeta128 Hx_pos (proj1 Hzeta128))
    as [Herror128_pos Herror128_lt].
  destruct
    (positive_lagrange_factor_is_strictly_smaller
      130%nat x zeta129 Hx_pos (proj1 Hzeta129))
    as [Herror129_pos Herror129_lt].

  repeat split.
  - nra.
  - nra.
  - rewrite factorial_R_eq_INR_fact. nra.
  - rewrite factorial_R_eq_INR_fact. nra.
Qed.

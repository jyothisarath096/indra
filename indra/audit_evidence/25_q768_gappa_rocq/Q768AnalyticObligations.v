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

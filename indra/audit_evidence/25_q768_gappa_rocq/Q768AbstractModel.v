From Stdlib Require Import NArith ZArith Reals Lia Psatz Field.
Require Import Q768AnalyticObligations.
Require Q768FiniteBounds.

Open Scope N_scope.

Definition q768_scale : N := 2 ^ 768.
Definition ceil_div (n d : N) : N := (n + d - 1) / d.

Record interval := { ilo : N; ihi : N }.

Definition imul (a b : interval) : interval :=
  {| ilo := (a.(ilo) * b.(ilo)) / q768_scale;
     ihi := ceil_div (a.(ihi) * b.(ihi)) q768_scale |}.

Definition idivi (a : interval) (d : N) : interval :=
  {| ilo := a.(ilo) / d;
     ihi := ceil_div a.(ihi) d |}.

Record log_acc := { log_power : interval; log_sum : interval }.

Fixpoint log_recurrence
    (remaining n : nat) (y2 : interval) (st : log_acc) : log_acc :=
  match remaining with
  | O => st
  | S remaining' =>
      let d := N.of_nat (2 * n + 1) in
      let t := idivi st.(log_power) d in
      let with_term :=
        {| log_power := st.(log_power);
           log_sum := {| ilo := st.(log_sum).(ilo) + t.(ilo);
                         ihi := st.(log_sum).(ihi) + t.(ihi) |} |} in
      match remaining' with
      | O => with_term
      | S _ =>
          log_recurrence remaining' (Nat.succ n) y2
            {| log_power := imul with_term.(log_power) y2;
               log_sum := with_term.(log_sum) |}
      end
  end.

Definition certified_log_model (f : N) : interval :=
  let fq := f * 2 ^ (768 - 64) in
  let den := 2 * q768_scale - fq in
  let y := {| ilo := (fq * q768_scale) / den;
              ihi := ceil_div (fq * q768_scale) den |} in
  let y2 := imul y y in
  let final := log_recurrence 256%nat 0%nat y2
                 {| log_power := y; log_sum := {| ilo := 0; ihi := 0 |} |} in
  let y513 := imul final.(log_power) y2 in
  let tail := ceil_div (2 * y513.(ihi) * q768_scale)
                       (513 * (q768_scale - y2.(ihi))) in
  {| ilo := 2 * final.(log_sum).(ilo);
     ihi := 2 * final.(log_sum).(ihi) + tail |}.

Record phi_acc := { phi_term : interval; phi_sum : Z }.

Definition selected_endpoint (lower odd : bool) (t : interval) : N :=
  if odd then if lower then t.(ilo) else t.(ihi)
  else if lower then t.(ihi) else t.(ilo).

Fixpoint phi_recurrence
    (remaining k : nat) (zi : interval) (lower : bool) (st : phi_acc) : phi_acc :=
  match remaining with
  | O => st
  | S remaining' =>
      let current_term :=
        if Nat.eqb k 1%nat then st.(phi_term)
        else idivi (imul st.(phi_term) zi) (N.of_nat k) in
      let odd := Nat.odd k in
      let v := Z.of_N (selected_endpoint lower odd current_term) in
      let next_sum := if odd then (st.(phi_sum) + v)%Z else (st.(phi_sum) - v)%Z in
      phi_recurrence remaining' (Nat.succ k) zi lower
        {| phi_term := current_term; phi_sum := next_sum |}
  end.

Definition phi_model (z : N) (terms : nat) (lower : bool) : N :=
  let zi := {| ilo := z; ihi := z |} in
  let final := phi_recurrence terms 1%nat zi lower
                 {| phi_term := zi; phi_sum := 0%Z |} in
  Z.to_N final.(phi_sum).

Definition certificate_model (f w total : N) : N * N :=
  let l := certified_log_model f in
  let zlo := (l.(ilo) * w) / total in
  let zhi := ceil_div (l.(ihi) * w) total in
  (N.min q768_scale (phi_model zlo 128%nat true),
   N.min q768_scale (phi_model zhi 129%nat false)).

Definition NR (n : N) : R := IZR (Z.of_N n).

Open Scope R_scope.

Definition phi_argument (f w total : N) : R :=
  let fr := NR f / NR (2 ^ 64)%N in
  let alpha := NR w / NR total in
  alpha * (- ln (1 - fr)).

Definition true_probability (f w total : N) : R :=
  1 - exp (- phi_argument f w total).

Lemma true_probability_at_zero_phi_argument :
  forall f w total : N,
    phi_argument f w total = 0 ->
    true_probability f w total = 0.
Proof.
  intros f w total Hzero.
  unfold true_probability. rewrite Hzero, Ropp_0, exp_0. ring.
Qed.

Definition admissible (f w total : N) : Prop :=
  (1 <= f <= 2 ^ 63)%N /\ (1 <= w)%N /\ (w <= total)%N /\
  (total <= 2 ^ 64 - 1)%N.

(* Exact integer/real bridge used by the recurrence-soundness proof below. *)
Lemma NR_le : forall a b : N, (a <= b)%N -> NR a <= NR b.
Proof.
  intros a b Hab. unfold NR. apply IZR_le. now apply N2Z.inj_le.
Qed.

Lemma NR_lt : forall a b : N, (a < b)%N -> NR a < NR b.
Proof.
  intros a b Hab. unfold NR. apply IZR_lt. now apply N2Z.inj_lt.
Qed.

Lemma NR_nonnegative : forall a : N, 0 <= NR a.
Proof. intro a. change (NR 0 <= NR a). apply NR_le. apply N.le_0_l. Qed.

Lemma NR_add : forall a b : N, NR (a + b) = NR a + NR b.
Proof.
  intros a b. unfold NR. rewrite N2Z.inj_add, plus_IZR. reflexivity.
Qed.

Lemma NR_mul : forall a b : N, NR (a * b) = NR a * NR b.
Proof.
  intros a b. unfold NR. rewrite N2Z.inj_mul, mult_IZR. reflexivity.
Qed.

Lemma NR_sub : forall a b : N,
  (b <= a)%N -> NR (a - b) = NR a - NR b.
Proof.
  intros a b Hba. unfold NR. rewrite N2Z.inj_sub by exact Hba.
  rewrite minus_IZR. reflexivity.
Qed.

Lemma positive_NR : forall a : N, (a <> 0)%N -> 0 < NR a.
Proof. intros a Ha. change (NR 0 < NR a). apply NR_lt. lia. Qed.

Lemma floor_div_N_spec : forall n d : N,
  (d <> 0)%N -> (d * (n / d) <= n < d * (n / d + 1))%N.
Proof.
  intros n d Hd. split.
  - apply N.mul_div_le. exact Hd.
  - pose proof (N.div_mod n d Hd) as Heq.
    pose proof (N.mod_lt n d Hd) as Hmod.
    set (q := (n / d)%N) in *. nia.
Qed.

Lemma ceil_div_N_upper : forall n d : N,
  (d <> 0)%N -> (n <= d * ceil_div n d)%N.
Proof.
  intros n d Hd. unfold ceil_div.
  pose proof (N.div_mod (n + d - 1) d Hd) as Heq.
  pose proof (N.mod_lt (n + d - 1) d Hd) as Hmod.
  destruct (N.eq_dec n 0) as [-> | Hn].
  - apply N.le_0_l.
  - assert (0 < n)%N by lia.
    set (q := ((n + d - 1) / d)%N) in *.
    set (r := ((n + d - 1) mod d)%N) in *. nia.
Qed.

Lemma ceil_div_N_below_next : forall n d : N,
  (d <> 0)%N -> (d * ceil_div n d < n + d)%N.
Proof.
  intros n d Hd. unfold ceil_div.
  pose proof (N.div_mod (n + d - 1) d Hd) as Heq.
  pose proof (N.mod_lt (n + d - 1) d Hd) as Hmod.
  destruct (N.eq_dec n 0) as [-> | Hn].
  - simpl. pose proof (N.mul_div_le (d - 1) d Hd). nia.
  - assert (0 < n)%N by lia.
    set (q := ((n + d - 1) / d)%N) in *.
    set (r := ((n + d - 1) mod d)%N) in *. nia.
Qed.

Lemma ceil_div_N_gap : forall n d : N,
  (d <> 0)%N -> (ceil_div n d <= n / d + 1)%N.
Proof.
  intros n d Hd. unfold ceil_div.
  assert (Hlt : ((n + d - 1) / d < n / d + 2)%N).
  {
    apply N.div_lt_upper_bound; [exact Hd |].
    pose proof (floor_div_N_spec n d Hd). nia.
  }
  lia.
Qed.

Lemma floor_div_R_lower : forall n d : N,
  (d <> 0)%N -> NR (n / d) <= NR n / NR d.
Proof.
  intros n d Hd.
  assert (HdR : 0 < NR d) by (apply positive_NR; exact Hd).
  assert (HdR0 : NR d <> 0) by lra.
  apply (Rmult_le_reg_r (NR d)); [exact HdR |].
  replace (NR n / NR d * NR d) with (NR n) by (field; exact HdR0).
  rewrite <- NR_mul. apply NR_le.
  rewrite N.mul_comm. apply N.mul_div_le. exact Hd.
Qed.

Lemma ceil_div_R_upper : forall n d : N,
  (d <> 0)%N -> NR n / NR d <= NR (ceil_div n d).
Proof.
  intros n d Hd.
  assert (HdR : 0 < NR d) by (apply positive_NR; exact Hd).
  assert (HdR0 : NR d <> 0) by lra.
  apply (Rmult_le_reg_r (NR d)); [exact HdR |].
  replace (NR n / NR d * NR d) with (NR n) by (field; exact HdR0).
  rewrite <- NR_mul. apply NR_le. rewrite N.mul_comm.
  apply ceil_div_N_upper. exact Hd.
Qed.

Definition interval_contains (a : interval) (x : R) : Prop :=
  NR a.(ilo) <= x <= NR a.(ihi).

Lemma interval_contains_nonnegative : forall a x,
  interval_contains a x -> 0 <= x.
Proof.
  intros a x H. eapply Rle_trans; [apply NR_nonnegative | exact (proj1 H)].
Qed.

Lemma interval_add_contains : forall a b x y,
  interval_contains a x -> interval_contains b y ->
  interval_contains
    {| ilo := a.(ilo) + b.(ilo); ihi := a.(ihi) + b.(ihi) |}
    (x + y).
Proof.
  intros a b x y Ha Hb. unfold interval_contains in *; simpl.
  repeat rewrite NR_add. lra.
Qed.

Lemma interval_scale_contains : forall c a x,
  interval_contains a x ->
  interval_contains
    {| ilo := c * a.(ilo); ihi := c * a.(ihi) |}
    (NR c * x).
Proof.
  intros c a x Ha. unfold interval_contains in *; simpl.
  repeat rewrite NR_mul.
  pose proof (NR_nonnegative c). nra.
Qed.

Lemma imul_contains : forall a b x y,
  interval_contains a x -> interval_contains b y ->
  interval_contains (imul a b) (x * y / NR q768_scale).
Proof.
  intros a b x y Ha Hb.
  assert (HS : (q768_scale <> 0)%N) by
    (unfold q768_scale; vm_compute; discriminate).
  assert (HSR : 0 < NR q768_scale) by (apply positive_NR; exact HS).
  assert (Hx : 0 <= x) by (eapply interval_contains_nonnegative; eauto).
  assert (Hy : 0 <= y) by (eapply interval_contains_nonnegative; eauto).
  pose proof (NR_nonnegative a.(ilo)) as Halo0.
  pose proof (NR_nonnegative b.(ilo)) as Hblo0.
  pose proof (NR_nonnegative a.(ihi)) as Hahi0.
  pose proof (NR_nonnegative b.(ihi)) as Hbhi0.
  unfold interval_contains, imul; simpl.
  split.
  - eapply Rle_trans; [apply floor_div_R_lower; exact HS |].
    rewrite NR_mul.
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat; exact HSR.
    - apply Rmult_le_compat; [exact Halo0 | exact Hblo0 | exact (proj1 Ha) | exact (proj1 Hb)].
  - eapply Rle_trans; [|apply ceil_div_R_upper; exact HS].
    rewrite NR_mul.
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat; exact HSR.
    - apply Rmult_le_compat; [exact Hx | exact Hy | exact (proj2 Ha) | exact (proj2 Hb)].
Qed.

Lemma idivi_contains : forall a x d,
  (d <> 0)%N -> interval_contains a x ->
  interval_contains (idivi a d) (x / NR d).
Proof.
  intros a x d Hd Ha. unfold interval_contains, idivi; simpl.
  assert (HdR : 0 < NR d) by (apply positive_NR; exact Hd).
  split.
  - eapply Rle_trans; [apply floor_div_R_lower; exact Hd |].
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat; exact HdR.
    - exact (proj1 Ha).
  - eapply Rle_trans; [|apply ceil_div_R_upper; exact Hd].
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat; exact HdR.
    - exact (proj2 Ha).
Qed.

Lemma ceil_div_N_mono : forall a b d : N,
  (a <= b)%N -> (ceil_div a d <= ceil_div b d)%N.
Proof.
  intros a b d Hab. unfold ceil_div.
  destruct (N.eq_dec d 0) as [-> | Hd].
  - rewrite !N.div_0_r. apply N.le_refl.
  - apply N.div_le_mono; [exact Hd |].
    apply N.sub_le_mono_r, N.add_le_mono_r. exact Hab.
Qed.

Lemma floor_le_ceil : forall n d : N,
  (d <> 0)%N -> (n / d <= ceil_div n d)%N.
Proof.
  intros n d Hd. apply N.div_le_upper_bound; [exact Hd |].
  apply ceil_div_N_upper. exact Hd.
Qed.

Lemma quotient_difference : forall n m d : N,
  (d <> 0)%N -> (m <= n)%N ->
  (n / d - m / d <= ceil_div (n - m) d)%N.
Proof.
  intros n m d Hd Hmn.
  pose proof (N.div_mod n d Hd) as En.
  pose proof (N.mod_lt n d Hd) as Rn.
  pose proof (N.div_mod m d Hd) as Em.
  pose proof (N.mod_lt m d Hd) as Rm.
  pose proof (ceil_div_N_upper (n - m) d Hd) as Ec.
  assert (n = m + (n - m))%N by nia.
  set (qn := (n / d)%N) in *.
  set (qm := (m / d)%N) in *.
  set (rn := (n mod d)%N) in *.
  set (rm := (m mod d)%N) in *.
  set (c := ceil_div (n - m) d) in *. nia.
Qed.

Lemma rounded_interval_width : forall hi lo d : N,
  (d <> 0)%N -> (lo <= hi)%N ->
  (ceil_div hi d - lo / d <= ceil_div (hi - lo) d + 1)%N.
Proof.
  intros hi lo d Hd Horder.
  pose proof (ceil_div_N_gap hi d Hd).
  pose proof (quotient_difference hi lo d Hd Horder). nia.
Qed.

Definition interval_bounded (a : interval) (upper width : N) : Prop :=
  (a.(ihi) <= upper)%N /\
  (a.(ihi) - a.(ilo) <= width)%N /\
  (a.(ilo) <= a.(ihi))%N.

Lemma interval_product_difference : forall a b au bu aw bw,
  interval_bounded a au aw -> interval_bounded b bu bw ->
  (a.(ihi) * b.(ihi) - a.(ilo) * b.(ilo)
    <= bu * aw + au * bw)%N.
Proof.
  intros a b au bu aw bw Ha Hb.
  destruct Ha as [Hau [Haw Hao]].
  destruct Hb as [Hbu [Hbw Hbo]].
  assert (a.(ihi) = a.(ilo) + (a.(ihi) - a.(ilo)))%N by nia.
  assert (b.(ihi) = b.(ilo) + (b.(ihi) - b.(ilo)))%N by nia.
  nia.
Qed.

Lemma imul_bounded : forall a b au bu aw bw,
  interval_bounded a au aw -> interval_bounded b bu bw ->
  interval_bounded (imul a b)
    (fst (Q768FiniteBounds.mul_bound au bu aw bw))
    (snd (Q768FiniteBounds.mul_bound au bu aw bw)).
Proof.
  intros a b au bu aw bw Ha Hb.
  assert (HS : (q768_scale <> 0)%N) by
    (unfold q768_scale; vm_compute; discriminate).
  destruct Ha as [Hau [Haw Hao]].
  destruct Hb as [Hbu [Hbw Hbo]].
  unfold Q768FiniteBounds.mul_bound, Q768FiniteBounds.q768_scale.
  change Q768FiniteBounds.ceil_div with ceil_div.
  unfold imul; simpl. repeat split.
  - apply ceil_div_N_mono. nia.
  - eapply N.le_trans.
    + apply rounded_interval_width; [exact HS |]. nia.
    + apply N.add_le_mono_r. apply ceil_div_N_mono.
      apply interval_product_difference; repeat split; assumption.
  - eapply N.le_trans with ((a.(ihi) * b.(ihi)) / q768_scale)%N.
    + apply N.div_le_mono; [exact HS |]. nia.
    + apply floor_le_ceil. exact HS.
Qed.

Lemma idivi_bounded : forall a au aw d,
  (d <> 0)%N -> interval_bounded a au aw ->
  interval_bounded (idivi a d)
    (fst (Q768FiniteBounds.div_scalar_bound au aw d))
    (snd (Q768FiniteBounds.div_scalar_bound au aw d)).
Proof.
  intros a au aw d Hd Ha.
  destruct Ha as [Hau [Haw Hao]].
  unfold Q768FiniteBounds.div_scalar_bound.
  change Q768FiniteBounds.ceil_div with ceil_div.
  unfold idivi; simpl. repeat split.
  - apply ceil_div_N_mono. exact Hau.
  - eapply N.le_trans.
    + apply rounded_interval_width; [exact Hd | exact Hao].
    + apply N.add_le_mono_r, ceil_div_N_mono. exact Haw.
  - eapply N.le_trans with (a.(ihi) / d)%N.
    + apply N.div_le_mono; [exact Hd | exact Hao].
    + apply floor_le_ceil. exact Hd.
Qed.

Lemma interval_add_bounded : forall a b au bu aw bw,
  interval_bounded a au aw -> interval_bounded b bu bw ->
  interval_bounded
    {| ilo := a.(ilo) + b.(ilo); ihi := a.(ihi) + b.(ihi) |}
    (au + bu) (aw + bw).
Proof.
  intros a b au bu aw bw Ha Hb.
  destruct Ha as [Hau [Haw Hao]].
  destruct Hb as [Hbu [Hbw Hbo]]. simpl. repeat split.
  - apply N.add_le_mono; assumption.
  - change
      ((a.(ihi) + b.(ihi)) - (a.(ilo) + b.(ilo)) <= aw + bw)%N.
    rewrite N.sub_add_distr.
    rewrite (N.add_comm a.(ihi) b.(ihi)).
    rewrite <- (N.add_sub_assoc b.(ihi) a.(ihi) a.(ilo) Hao).
    rewrite N.add_comm.
    rewrite <- (N.add_sub_assoc (a.(ihi) - a.(ilo)) b.(ihi) b.(ilo) Hbo).
    apply N.add_le_mono; assumption.
  - apply N.add_le_mono; assumption.
Qed.

Definition log_acc_bounded
    (st : log_acc) (bst : Q768FiniteBounds.log_state) : Prop :=
  interval_bounded st.(log_power) bst.(Q768FiniteBounds.power_hi)
    bst.(Q768FiniteBounds.power_width) /\
  interval_bounded st.(log_sum) bst.(Q768FiniteBounds.sum_hi)
    bst.(Q768FiniteBounds.sum_width).

Lemma log_recurrence_bounded : forall remaining n y2 st bst y2_hi y2_width,
  interval_bounded y2 y2_hi y2_width ->
  log_acc_bounded st bst ->
  log_acc_bounded
    (log_recurrence remaining n y2 st)
    (Q768FiniteBounds.log_terms remaining n
      y2_hi y2_width bst).
Proof.
  induction remaining as [|remaining IH];
    intros n y2 st bst y2_hi y2_width Hy2 Hst.
  - exact Hst.
  - cbn [log_recurrence Q768FiniteBounds.log_terms].
    set (d := N.of_nat (2 * n + 1)).
    assert (Hd : (d <> 0)%N).
    {
      unfold d. intro Heq.
      change (N.of_nat (2 * n + 1) = N.of_nat 0) in Heq.
      apply Nat2N.inj_iff in Heq. lia.
    }
    destruct Hst as [Hpower Hsum].
    pose proof (idivi_bounded st.(log_power)
      bst.(Q768FiniteBounds.power_hi)
      bst.(Q768FiniteBounds.power_width) d Hd Hpower) as Hterm.
    pose proof (interval_add_bounded st.(log_sum) (idivi st.(log_power) d)
      bst.(Q768FiniteBounds.sum_hi)
      (fst (Q768FiniteBounds.div_scalar_bound
        bst.(Q768FiniteBounds.power_hi)
        bst.(Q768FiniteBounds.power_width) d))
      bst.(Q768FiniteBounds.sum_width)
      (snd (Q768FiniteBounds.div_scalar_bound
        bst.(Q768FiniteBounds.power_hi)
        bst.(Q768FiniteBounds.power_width) d))
      Hsum Hterm) as Hsum_next.
    destruct remaining as [|remaining'].
    + split; assumption.
    + apply IH; [exact Hy2 |]. split.
      * unfold Q768FiniteBounds.advance_power; simpl.
        apply imul_bounded; assumption.
      * exact Hsum_next.
Qed.

Lemma ceil_div_N_le_of_multiple : forall n d q : N,
  (d <> 0)%N -> (n <= d * q)%N -> (ceil_div n d <= q)%N.
Proof.
  intros n d q Hd Hn.
  assert (Hlt : (n + d - 1 < d * (q + 1))%N) by nia.
  unfold ceil_div. apply N.div_lt_upper_bound in Hlt; [lia | exact Hd].
Qed.

Lemma ceil_div_den_antitone : forall n small large : N,
  (small <> 0)%N -> (small <= large)%N ->
  (ceil_div n large <= ceil_div n small)%N.
Proof.
  intros n small large Hsmall Horder.
  destruct (N.eq_dec large 0) as [Hlarge | Hlarge].
  - subst large. lia.
  - apply ceil_div_N_le_of_multiple; [exact Hlarge |].
    eapply N.le_trans; [apply ceil_div_N_upper; exact Hsmall |].
    apply N.mul_le_mono_r. exact Horder.
Qed.

Lemma q768_shift_identity :
  (2 * (2 ^ 63 * 2 ^ (768 - 64)) = q768_scale)%N.
Proof. vm_compute. reflexivity. Qed.

Lemma q768_factor_identity :
  (2 ^ (768 - 64) * 2 ^ 64 = q768_scale)%N.
Proof. vm_compute. reflexivity. Qed.

Lemma q768_nonzero : (q768_scale <> 0)%N.
Proof. unfold q768_scale. vm_compute. discriminate. Qed.

Lemma NR_of_nat : forall n : nat, NR (N.of_nat n) = INR n.
Proof.
  intro n. unfold NR. rewrite INR_IZR_INZ. f_equal.
  induction n as [|n IH]; [reflexivity |].
  rewrite Nat2N.inj_succ, Znat.Nat2Z.inj_succ, N2Z.inj_succ, IH.
  reflexivity.
Qed.

Lemma initial_y_contains : forall f,
  (f <= 2 ^ 63)%N ->
  let fq := (f * 2 ^ (768 - 64))%N in
  let den := (2 * q768_scale - fq)%N in
  interval_contains
    {| ilo := (fq * q768_scale) / den;
       ihi := ceil_div (fq * q768_scale) den |}
    (NR q768_scale *
      ((NR f / NR (2 ^ 64)%N) / (2 - NR f / NR (2 ^ 64)%N))).
Proof.
  intros f Hf. cbn zeta.
  set (fq := (f * 2 ^ (768 - 64))%N).
  set (den := (2 * q768_scale - fq)%N).
  assert (Hfq : (2 * fq <= q768_scale)%N).
  {
    unfold fq. pose proof (N.mul_le_mono_r f (2 ^ 63)
      (2 ^ (768 - 64)) Hf).
    rewrite <- q768_shift_identity. nia.
  }
  assert (Hscale : (0 < q768_scale)%N) by
    (pose proof q768_nonzero; lia).
  assert (Hden : (den <> 0)%N) by (unfold den; lia).
  assert (Hfq_le : (fq <= 2 * q768_scale)%N) by lia.
  assert (HdenR : NR den = 2 * NR q768_scale - NR fq).
  {
    unfold den. rewrite NR_sub by exact Hfq_le. rewrite NR_mul. simpl.
    unfold NR at 1. simpl. ring.
  }
  assert (HscaleR : 0 < NR q768_scale) by
    (apply positive_NR; exact q768_nonzero).
  assert (H64 : (NR (2 ^ 64)%N <> 0)) by
    (apply Rgt_not_eq, positive_NR; vm_compute; discriminate).
  assert (Hscaled :
    NR fq / NR q768_scale = NR f / NR (2 ^ 64)%N).
  {
    assert (Hscale0 : NR q768_scale <> 0) by lra.
    assert (Hinteger :
      (fq * 2 ^ 64 = f * q768_scale)%N).
    {
      unfold fq. rewrite <- N.mul_assoc, q768_factor_identity. reflexivity.
    }
    assert (Hcross :
      NR fq * NR (2 ^ 64)%N = NR f * NR q768_scale).
    { repeat rewrite <- NR_mul. now rewrite Hinteger. }
    rewrite <- (Rdiv_mult_r_r (NR (2 ^ 64)%N) (NR fq)
      (NR q768_scale) H64).
    rewrite Hcross, (Rmult_comm (NR q768_scale) (NR (2 ^ 64)%N)).
    apply Rdiv_mult_r_r. exact Hscale0.
  }
  assert (Heq :
    NR (fq * q768_scale) / NR den =
      NR q768_scale *
        ((NR f / NR (2 ^ 64)%N) / (2 - NR f / NR (2 ^ 64)%N))).
  {
    rewrite NR_mul, HdenR, <- Hscaled.
    assert (Hscale0 : NR q768_scale <> 0) by lra.
    assert (Hdiff : 2 * NR q768_scale - NR fq <> 0).
    { rewrite <- HdenR. apply Rgt_not_eq, positive_NR. exact Hden. }
    field; try assumption; try lra.
  }
  unfold interval_contains. cbn [ilo ihi]. split.
  - eapply Rle_trans with (NR (fq * q768_scale) / NR den).
    + apply floor_div_R_lower. exact Hden.
    + rewrite Heq. apply Rle_refl.
  - eapply Rle_trans with (NR (fq * q768_scale) / NR den).
    + rewrite Heq. apply Rle_refl.
    + apply ceil_div_R_upper. exact Hden.
Qed.

Lemma initial_y_bounded : forall f,
  (f <= 2 ^ 63)%N ->
  let fq := (f * 2 ^ (768 - 64))%N in
  let den := (2 * q768_scale - fq)%N in
  interval_bounded
    {| ilo := (fq * q768_scale) / den;
       ihi := ceil_div (fq * q768_scale) den |}
    Q768FiniteBounds.y_hi Q768FiniteBounds.y_width.
Proof.
  intros f Hf. cbn zeta.
  set (fq := (f * 2 ^ (768 - 64))%N).
  set (den := (2 * q768_scale - fq)%N).
  assert (Hfq : (2 * fq <= q768_scale)%N).
  {
    unfold fq. pose proof (N.mul_le_mono_r f (2 ^ 63)
      (2 ^ (768 - 64)) Hf).
    rewrite <- q768_shift_identity. nia.
  }
  assert (Hscale : (0 < q768_scale)%N) by
    (pose proof q768_nonzero; lia).
  assert (Hden : (den <> 0)%N) by (unfold den; lia).
  assert (Hthree : (3 * fq <= den)%N) by (unfold den; lia).
  assert (Hyhi : (3 * Q768FiniteBounds.y_hi = q768_scale + 2)%N).
  { vm_compute. reflexivity. }
  unfold interval_bounded; simpl. repeat split.
  - apply ceil_div_N_le_of_multiple; [exact Hden |].
    nia.
  - unfold Q768FiniteBounds.y_width.
    pose proof (ceil_div_N_gap (fq * q768_scale) den Hden).
    pose proof (floor_le_ceil (fq * q768_scale) den Hden). nia.
  - apply floor_le_ceil. exact Hden.
Qed.

Lemma log_recurrence_256_bounded : forall y2 initial,
  interval_bounded y2 Q768FiniteBounds.y2_hi
    Q768FiniteBounds.y2_width ->
  log_acc_bounded initial Q768FiniteBounds.initial_log_state ->
  log_acc_bounded (log_recurrence 256%nat 0%nat y2 initial)
    Q768FiniteBounds.final_log_state.
Proof.
  intros y2 initial Hy2 Hinitial.
  unfold Q768FiniteBounds.final_log_state.
  apply log_recurrence_bounded; assumption.
Qed.

Opaque Q768FiniteBounds.final_log_state.

Lemma finite_log_hi_shape :
  Q768FiniteBounds.log_hi =
    (2 * Q768FiniteBounds.final_log_state.(Q768FiniteBounds.sum_hi) +
      Q768FiniteBounds.log_tail)%N.
Proof. reflexivity. Qed.

Lemma finite_log_width_shape :
  Q768FiniteBounds.log_width =
    (2 * Q768FiniteBounds.final_log_state.(Q768FiniteBounds.sum_width) +
      Q768FiniteBounds.log_tail)%N.
Proof. reflexivity. Qed.

Lemma certified_log_model_bounded : forall f,
  (f <= 2 ^ 63)%N ->
  interval_bounded (certified_log_model f)
    Q768FiniteBounds.log_hi Q768FiniteBounds.log_width.
Proof.
  intros f Hf.
  unfold certified_log_model.
  set (fq := (f * 2 ^ (768 - 64))%N).
  set (den := (2 * q768_scale - fq)%N).
  set (y := {| ilo := (fq * q768_scale) / den;
               ihi := ceil_div (fq * q768_scale) den |}).
  set (y2 := imul y y).
  set (initial := {| log_power := y;
                     log_sum := {| ilo := 0; ihi := 0 |} |}).
  set (final := log_recurrence 256%nat 0%nat y2 initial).
  set (y513 := imul final.(log_power) y2).
  set (tail := ceil_div (2 * y513.(ihi) * q768_scale)
    (513 * (q768_scale - y2.(ihi)))).
  assert (Hy : interval_bounded y Q768FiniteBounds.y_hi
    Q768FiniteBounds.y_width).
  { unfold y, fq, den. apply initial_y_bounded. exact Hf. }
  assert (Hy2 : interval_bounded y2 Q768FiniteBounds.y2_hi
    Q768FiniteBounds.y2_width).
  {
    unfold y2, Q768FiniteBounds.y2_hi, Q768FiniteBounds.y2_width,
      Q768FiniteBounds.y2. apply imul_bounded; exact Hy.
  }
  assert (Hinitial : log_acc_bounded initial
    Q768FiniteBounds.initial_log_state).
  {
    unfold initial, Q768FiniteBounds.initial_log_state,
      log_acc_bounded; simpl. split; [exact Hy |].
    unfold interval_bounded; simpl. repeat split; apply N.le_refl.
  }
  pose proof (log_recurrence_256_bounded y2 initial Hy2 Hinitial) as Hfinal.
  fold final in Hfinal.
  destruct Hfinal as [Hpower Hsum].
  assert (Hy513 : interval_bounded y513
    (fst Q768FiniteBounds.y513) (snd Q768FiniteBounds.y513)).
  {
    unfold y513, Q768FiniteBounds.y513. apply imul_bounded; assumption.
  }
  destruct Hy2 as [Hy2hi [Hy2width Hy2order]].
  destruct Hy513 as [Hy513hi [Hy513width Hy513order]].
  destruct Hsum as [Hsumhi [Hsumwidth Hsumorder]].
  assert (Hfinite_den :
    (513 * (q768_scale - Q768FiniteBounds.y2_hi) <> 0)%N).
  { vm_compute. discriminate. }
  assert (Hactual_den :
    (513 * (q768_scale - y2.(ihi)) <> 0)%N).
  {
    assert (Q768FiniteBounds.y2_hi < q768_scale)%N.
    { vm_compute. reflexivity. }
    nia.
  }
  assert (Htail : (tail <= Q768FiniteBounds.log_tail)%N).
  {
    unfold tail, Q768FiniteBounds.log_tail.
    change Q768FiniteBounds.ceil_div with ceil_div.
    eapply N.le_trans.
    - apply ceil_div_N_mono, N.mul_le_mono_r, N.mul_le_mono_l.
      exact Hy513hi.
    - apply ceil_div_den_antitone; [exact Hfinite_den |].
      apply N.mul_le_mono_l, N.sub_le_mono_l. exact Hy2hi.
  }
  unfold interval_bounded. cbn [ilo ihi].
  rewrite finite_log_hi_shape, finite_log_width_shape. repeat split.
  - nia.
  - assert (final.(log_sum).(ihi) = final.(log_sum).(ilo) +
      (final.(log_sum).(ihi) - final.(log_sum).(ilo)))%N by nia.
    nia.
  - nia.
Qed.

Lemma imul_scaled_contains : forall a b x y,
  interval_contains a (NR q768_scale * x) ->
  interval_contains b (NR q768_scale * y) ->
  interval_contains (imul a b) (NR q768_scale * (x * y)).
Proof.
  intros a b x y Ha Hb.
  pose proof (imul_contains a b (NR q768_scale * x)
    (NR q768_scale * y) Ha Hb) as H.
  replace
    ((NR q768_scale * x) * (NR q768_scale * y) / NR q768_scale)
    with (NR q768_scale * (x * y)) in H.
  - exact H.
  - assert (NR q768_scale <> 0) by
      (apply Rgt_not_eq, positive_NR; exact q768_nonzero).
    field; assumption.
Qed.

Lemma idivi_scaled_contains : forall a x d,
  (d <> 0)%N -> interval_contains a (NR q768_scale * x) ->
  interval_contains (idivi a d)
    (NR q768_scale * (x / NR d)).
Proof.
  intros a x d Hd Ha.
  pose proof (idivi_contains a (NR q768_scale * x) d Hd Ha) as H.
  replace (NR q768_scale * x / NR d)
    with (NR q768_scale * (x / NR d)) in H by (unfold Rdiv; ring).
  exact H.
Qed.

Fixpoint log_real_recurrence
    (remaining n : nat) (y2 power sum : R) : R * R :=
  match remaining with
  | O => (power, sum)
  | S remaining' =>
      let d := INR (2 * n + 1) in
      let with_sum := sum + power / d in
      match remaining' with
      | O => (power, with_sum)
      | S _ =>
          log_real_recurrence remaining' (Nat.succ n) y2
            (power * y2) with_sum
      end
  end.

Definition log_acc_contains (st : log_acc) (power sum : R) : Prop :=
  interval_contains st.(log_power) (NR q768_scale * power) /\
  interval_contains st.(log_sum) (NR q768_scale * sum).

Lemma log_recurrence_contains : forall remaining n y2 st y2r power sum,
  interval_contains y2 (NR q768_scale * y2r) ->
  log_acc_contains st power sum ->
  let real_final := log_real_recurrence remaining n y2r power sum in
  log_acc_contains (log_recurrence remaining n y2 st)
    (fst real_final) (snd real_final).
Proof.
  induction remaining as [|remaining IH];
    intros n y2 st y2r power sum Hy2 Hst.
  - exact Hst.
  - cbn [log_recurrence log_real_recurrence].
    set (d := N.of_nat (2 * n + 1)).
    assert (Hd : (d <> 0)%N).
    {
      unfold d. intro Heq.
      change (N.of_nat (2 * n + 1) = N.of_nat 0) in Heq.
      apply Nat2N.inj_iff in Heq. lia.
    }
    destruct Hst as [Hpower Hsum].
    pose proof (idivi_scaled_contains st.(log_power) power d Hd Hpower)
      as Hterm.
    unfold d in Hterm. rewrite NR_of_nat in Hterm.
    pose proof (interval_add_contains st.(log_sum)
      (idivi st.(log_power) d)
      (NR q768_scale * sum)
      (NR q768_scale * (power / INR (2 * n + 1)))
      Hsum Hterm) as Hsum_next.
    replace
      (NR q768_scale * sum +
        NR q768_scale * (power / INR (2 * n + 1)))
      with
      (NR q768_scale * (sum + power / INR (2 * n + 1)))
      in Hsum_next by ring.
    destruct remaining as [|remaining'].
    + split; assumption.
    + apply IH; [exact Hy2 |]. split.
      * apply imul_scaled_contains; assumption.
      * exact Hsum_next.
Qed.

Lemma log_real_recurrence_powers : forall r n y,
  log_real_recurrence (S r) n (y ^ 2)
    (y ^ (2 * n + 1)) (log_partial n y / 2) =
  (y ^ (2 * (n + r) + 1), log_partial (n + S r) y / 2).
Proof.
  induction r as [|r IH]; intros n y.
  - cbn [log_real_recurrence].
    replace (n + 0)%nat with n by lia.
    replace (n + 1)%nat with (S n) by lia.
    cbn [log_partial]. apply pair_equal_spec. split.
    + reflexivity.
    + change
        (log_partial n y / 2 + y ^ (2 * n + 1) / INR (2 * n + 1) =
          (log_partial n y +
            2 * y ^ (2 * n + 1) / INR (2 * n + 1)) / 2).
      field. apply not_0_INR. lia.
  - change
      (log_real_recurrence (S r) (S n) (y ^ 2)
        (y ^ (2 * n + 1) * y ^ 2)
        (log_partial n y / 2 +
          y ^ (2 * n + 1) / INR (2 * n + 1)) =
       (y ^ (2 * (n + S r) + 1),
        log_partial (n + S (S r)) y / 2)).
    replace (y ^ (2 * n + 1) * y ^ 2)
      with (y ^ (2 * S n + 1)).
    2: { rewrite <- pow_add. f_equal. lia. }
    replace
      (log_partial n y / 2 + y ^ (2 * n + 1) / INR (2 * n + 1))
      with (log_partial (S n) y / 2).
    2: { cbn [log_partial]. field. apply not_0_INR. lia. }
    rewrite IH.
    replace (S n + r)%nat with (n + S r)%nat by lia.
    replace (S n + S r)%nat with (n + S (S r))%nat by lia.
    reflexivity.
Qed.

Lemma div_mono_nonnegative : forall a upper small large : R,
  0 <= a <= upper -> 0 < small <= large ->
  a / large <= upper / small.
Proof.
  intros a upper small large Ha Hd. unfold Rdiv.
  eapply Rle_trans with (upper * / large).
  - apply Rmult_le_compat_r; [apply Rlt_le, Rinv_0_lt_compat; lra | lra].
  - apply Rmult_le_compat_l; [lra |].
    apply Rinv_le_contravar; lra.
Qed.

Lemma power64_double_power63 :
  NR (2 ^ 64)%N = 2 * NR (2 ^ 63)%N.
Proof.
  change (NR (2 ^ 64)%N = NR 2 * NR (2 ^ 63)%N).
  rewrite <- NR_mul. apply f_equal.
  vm_compute. reflexivity.
Qed.

Lemma production_y_domain : forall f,
  (1 <= f <= 2 ^ 63)%N ->
  let fr := NR f / NR (2 ^ 64)%N in
  0 < fr / (2 - fr) <= 1 / 3.
Proof.
  intros f [Hfpos Hfmax]. cbn zeta.
  assert (H64R : 0 < NR (2 ^ 64)%N) by
    (apply positive_NR; vm_compute; discriminate).
  assert (HfRpos : 0 < NR f) by
    (change (NR 0 < NR f); apply NR_lt; lia).
  assert (HfRmax : NR f <= NR (2 ^ 63)%N) by
    (apply NR_le; exact Hfmax).
  set (fr := NR f / NR (2 ^ 64)%N).
  assert (Hfrpos : 0 < fr) by
    (unfold fr; apply Rdiv_lt_0_compat; assumption).
  assert (Hfrhalf : fr <= 1 / 2).
  {
    apply (Rmult_le_reg_r (NR (2 ^ 64)%N)); [exact H64R |].
    unfold fr. replace
      (NR f / NR (2 ^ 64)%N * NR (2 ^ 64)%N)
      with (NR f) by (field; lra).
    rewrite power64_double_power63. nra.
  }
  assert (Hden : 0 < 2 - fr) by lra.
  split.
  - apply Rdiv_lt_0_compat; lra.
  - apply (Rmult_le_reg_r (3 * (2 - fr))); [nra |].
    replace (fr / (2 - fr) * (3 * (2 - fr))) with (3 * fr)
      by (field; lra).
    nra.
Qed.

Lemma certified_log_model_contains : forall f,
  (1 <= f <= 2 ^ 63)%N ->
  interval_contains (certified_log_model f)
    (NR q768_scale * (- ln (1 - NR f / NR (2 ^ 64)%N))).
Proof.
  intros f Hf.
  unfold certified_log_model.
  set (fq := (f * 2 ^ (768 - 64))%N).
  set (den := (2 * q768_scale - fq)%N).
  set (fr := NR f / NR (2 ^ 64)%N).
  set (yr := fr / (2 - fr)).
  set (y := {| ilo := (fq * q768_scale) / den;
               ihi := ceil_div (fq * q768_scale) den |}).
  set (y2 := imul y y).
  set (initial := {| log_power := y;
                     log_sum := {| ilo := 0; ihi := 0 |} |}).
  set (final := log_recurrence 256%nat 0%nat y2 initial).
  set (y513 := imul final.(log_power) y2).
  set (tail_den := (513 * (q768_scale - y2.(ihi)))%N).
  set (tail := ceil_div (2 * y513.(ihi) * q768_scale) tail_den).
  assert (Hydomain : 0 < yr <= 1 / 3).
  { unfold yr, fr. apply production_y_domain. exact Hf. }
  assert (Hy : interval_contains y (NR q768_scale * yr)).
  {
    unfold y, yr, fr, fq, den. apply initial_y_contains. exact (proj2 Hf).
  }
  assert (Hy2 : interval_contains y2 (NR q768_scale * (yr ^ 2))).
  { unfold y2. replace (yr ^ 2) with (yr * yr) by ring.
    apply imul_scaled_contains; exact Hy. }
  assert (Hinitial : log_acc_contains initial yr 0).
  {
    unfold log_acc_contains, initial. simpl. split; [exact Hy |].
    unfold interval_contains; simpl. rewrite Rmult_0_r.
    unfold NR. simpl. split; lra.
  }
  pose proof (log_recurrence_contains 256%nat 0%nat y2 initial
    (yr ^ 2) yr 0 Hy2 Hinitial) as Hfinal.
  pose proof (log_real_recurrence_powers 255%nat 0%nat yr) as Hreal.
  replace (yr ^ (2 * 0 + 1)) with yr in Hreal by (simpl; ring).
  replace (log_partial 0 yr / 2) with 0 in Hreal by
    (cbn [log_partial]; unfold Rdiv; ring).
  replace (yr ^ (2 * (0 + 255) + 1)) with (yr ^ 511) in Hreal
    by reflexivity.
  replace (log_partial (0 + 256) yr) with (log_partial 256 yr) in Hreal
    by reflexivity.
  rewrite Hreal in Hfinal.
  fold final in Hfinal. cbn [fst snd] in Hfinal.
  destruct Hfinal as [Hpower Hsum].
  assert (Hy513 : interval_contains y513
    (NR q768_scale * yr ^ 513)).
  {
    unfold y513. pose proof (imul_scaled_contains final.(log_power) y2
      (yr ^ 511) (yr ^ 2) Hpower Hy2) as H.
    replace (yr ^ 511 * yr ^ 2) with (yr ^ 513) in H.
    - exact H.
    - rewrite <- pow_add. reflexivity.
  }
  pose proof (certified_log_model_bounded f (proj2 Hf)) as Hbounded.
  unfold certified_log_model in Hbounded.
  fold fq den y y2 initial final y513 tail in Hbounded.
  destruct Hbounded as [_ [_ Hlogorder]].
  assert (Hy2bound : (y2.(ihi) <= Q768FiniteBounds.y2_hi)%N).
  {
    unfold y2. pose proof (initial_y_bounded f (proj2 Hf)) as Hyb.
    fold fq den y in Hyb.
    pose proof (imul_bounded y y Q768FiniteBounds.y_hi
      Q768FiniteBounds.y_hi Q768FiniteBounds.y_width
      Q768FiniteBounds.y_width Hyb Hyb) as Hb.
    unfold Q768FiniteBounds.y2_hi, Q768FiniteBounds.y2_width,
      Q768FiniteBounds.y2 in Hb. exact (proj1 Hb).
  }
  assert (Hy2lt : (y2.(ihi) < q768_scale)%N).
  { assert (Q768FiniteBounds.y2_hi < q768_scale)%N by
      (vm_compute; reflexivity). lia. }
  assert (Htailden : (tail_den <> 0)%N).
  { unfold tail_den. pose proof q768_nonzero. nia. }
  assert (Htail_upper :
    NR q768_scale *
      (2 * yr ^ 513 / (513 * (1 - yr ^ 2))) <= NR tail).
  {
    eapply Rle_trans.
    2: { unfold tail. apply ceil_div_R_upper. exact Htailden. }
    assert (HSR : 0 < NR q768_scale) by
      (apply positive_NR; exact q768_nonzero).
    assert (H513R : 0 < NR 513) by (apply positive_NR; discriminate).
    assert (Hy2upper : NR q768_scale * yr ^ 2 <= NR y2.(ihi))
      by exact (proj2 Hy2).
    assert (Hy513upper : NR q768_scale * yr ^ 513 <= NR y513.(ihi))
      by exact (proj2 Hy513).
    assert (Hcomputed_den : 0 < NR q768_scale - NR y2.(ihi)).
    { apply NR_lt in Hy2lt. lra. }
    assert (Hexact_den :
      0 < NR q768_scale - NR q768_scale * yr ^ 2) by nra.
    assert (Hratio := div_mono_nonnegative
      (2 * (NR q768_scale * yr ^ 513) * NR q768_scale)
      (2 * NR y513.(ihi) * NR q768_scale)
      (NR 513 * (NR q768_scale - NR y2.(ihi)))
      (NR 513 *
        (NR q768_scale - NR q768_scale * yr ^ 2))).
    assert (Hnumorder :
      0 <= 2 * (NR q768_scale * yr ^ 513) * NR q768_scale <=
        2 * NR y513.(ihi) * NR q768_scale).
    {
      pose proof (NR_nonnegative y513.(ihi)).
      assert (0 <= yr ^ 513) by (apply pow_le; lra).
      nra.
    }
    assert (Hdenorder :
      0 < NR 513 * (NR q768_scale - NR y2.(ihi)) <=
        NR 513 * (NR q768_scale - NR q768_scale * yr ^ 2)).
    { split; nra. }
    specialize (Hratio Hnumorder Hdenorder).
    unfold tail_den. repeat rewrite NR_mul. rewrite NR_sub by lia.
    replace (NR 513) with (513 : R) in * by
      (unfold NR; simpl; ring).
    assert (Hleft :
      NR q768_scale * (2 * yr ^ 513 / (513 * (1 - yr ^ 2))) =
      (2 * (NR q768_scale * yr ^ 513) * NR q768_scale) /
        (513 * (NR q768_scale - NR q768_scale * yr ^ 2))).
    { field; nra. }
    rewrite Hleft. exact Hratio.
  }
  pose proof (log_tail_after_exactly_256_terms yr Hydomain) as Hanalytic.
  pose proof (log_y_substitution_identity fr) as Hsubst.
  assert (Hfrdomain : 0 <= fr < 1).
  {
    unfold fr.
    assert (H64R : 0 < NR (2 ^ 64)%N) by
      (apply positive_NR; vm_compute; discriminate).
    assert (Hfnonneg : 0 <= NR f) by apply NR_nonnegative.
    assert (Hflt : NR f < NR (2 ^ 64)%N).
    { apply NR_lt. eapply N.le_lt_trans; [exact (proj2 Hf) |].
      vm_compute. reflexivity. }
    split.
    - unfold Rdiv. apply Rmult_le_pos; [exact Hfnonneg |].
      apply Rlt_le, Rinv_0_lt_compat. exact H64R.
    - apply (Rmult_lt_reg_r (NR (2 ^ 64)%N)); [exact H64R |].
      replace (NR f / NR (2 ^ 64)%N * NR (2 ^ 64)%N)
        with (NR f) by (field; lra).
      nra.
  }
  specialize (Hsubst Hfrdomain).
  fold fq den y y2 initial final y513 tail_den tail.
  unfold interval_contains in Hsum |- *. cbn [ilo ihi] in Hsum |- *.
  rewrite <- Hsubst.
  assert (HSR0 : 0 <= NR q768_scale) by apply NR_nonnegative.
  assert (Hsumlo :
    2 * NR final.(log_sum).(ilo) <=
      NR q768_scale * log_partial 256 yr).
  { pose proof (proj1 Hsum). nra. }
  assert (Hsumhi :
    NR q768_scale * log_partial 256 yr <=
      2 * NR final.(log_sum).(ihi)).
  { pose proof (proj2 Hsum). nra. }
  split.
  - rewrite NR_mul. replace (NR 2) with (2 : R) by
      (unfold NR; simpl; ring).
    eapply Rle_trans; [exact Hsumlo |].
    apply Rmult_le_compat_l; [exact HSR0 | exact (proj1 Hanalytic)].
  - assert (Hanalytic_upper :
      true_log_from_y yr <= log_partial 256 yr +
        2 * yr ^ 513 / (513 * (1 - yr ^ 2))) by
      (pose proof (proj2 Hanalytic); lra).
    eapply Rle_trans.
    + apply Rmult_le_compat_l; [exact HSR0 | exact Hanalytic_upper].
    + rewrite NR_add, NR_mul. replace (NR 2) with (2 : R) by
        (unfold NR; simpl; ring).
      nra.
Qed.

Lemma stake_scaled_contains : forall l exact w total,
  (total <> 0)%N -> (w <= total)%N ->
  interval_contains l (NR q768_scale * exact) ->
  interval_contains
    {| ilo := (l.(ilo) * w) / total;
       ihi := ceil_div (l.(ihi) * w) total |}
    (NR q768_scale * (NR w / NR total * exact)).
Proof.
  intros l exact w total Htotal Hw Hl.
  assert (HtotalR : 0 < NR total) by (apply positive_NR; exact Htotal).
  assert (HwR : 0 <= NR w) by apply NR_nonnegative.
  unfold interval_contains in *; simpl. split.
  - eapply Rle_trans; [apply floor_div_R_lower; exact Htotal |].
    rewrite NR_mul. unfold Rdiv at 1.
    replace (NR (ilo l) * NR w * / NR total)
      with (NR w / NR total * NR (ilo l)) by (unfold Rdiv; ring).
    replace (NR q768_scale * (NR w / NR total * exact))
      with (NR w / NR total * (NR q768_scale * exact)) by ring.
    apply Rmult_le_compat_l.
    + unfold Rdiv. apply Rmult_le_pos; [exact HwR |].
      apply Rlt_le, Rinv_0_lt_compat. exact HtotalR.
    + exact (proj1 Hl).
  - eapply Rle_trans; [|apply ceil_div_R_upper; exact Htotal].
    rewrite NR_mul. unfold Rdiv at 2.
    replace (NR (ihi l) * NR w * / NR total)
      with (NR w / NR total * NR (ihi l)) by (unfold Rdiv; ring).
    replace (NR q768_scale * (NR w / NR total * exact))
      with (NR w / NR total * (NR q768_scale * exact)) by ring.
    apply Rmult_le_compat_l.
    + unfold Rdiv. apply Rmult_le_pos; [exact HwR |].
      apply Rlt_le, Rinv_0_lt_compat. exact HtotalR.
    + exact (proj2 Hl).
Qed.

Lemma stake_scaled_bounded : forall l w total,
  (total <> 0)%N -> (w <= total)%N ->
  interval_bounded l Q768FiniteBounds.log_hi
    Q768FiniteBounds.log_width ->
  interval_bounded
    {| ilo := (l.(ilo) * w) / total;
       ihi := ceil_div (l.(ihi) * w) total |}
    Q768FiniteBounds.log_hi (Q768FiniteBounds.log_width + 1).
Proof.
  intros l w total Htotal Hw Hl.
  destruct Hl as [Hlhi [Hlwidth Hlorder]].
  unfold interval_bounded; simpl. repeat split.
  - eapply N.le_trans.
    + apply ceil_div_N_le_of_multiple; [exact Htotal |].
      rewrite (N.mul_comm total l.(ihi)).
      apply N.mul_le_mono_l. exact Hw.
    + exact Hlhi.
  - eapply N.le_trans.
    + apply rounded_interval_width; [exact Htotal |].
      apply N.mul_le_mono_r. exact Hlorder.
    + apply N.add_le_mono_r.
      apply ceil_div_N_le_of_multiple; [exact Htotal |].
      rewrite <- N.mul_sub_distr_r by exact Hlorder.
      eapply N.le_trans; [apply N.mul_le_mono_r; exact Hlwidth |].
      rewrite (N.mul_comm total Q768FiniteBounds.log_width).
      apply N.mul_le_mono_l. exact Hw.
  - eapply N.le_trans.
    + apply N.div_le_mono; [exact Htotal |].
      apply N.mul_le_mono_r. exact Hlorder.
    + apply floor_le_ceil. exact Htotal.
Qed.

Lemma certificate_log_and_stake_bridge : forall f w total,
  admissible f w total ->
  let l := certified_log_model f in
  let z :=
    {| ilo := (l.(ilo) * w) / total;
       ihi := ceil_div (l.(ihi) * w) total |} in
  interval_contains z (NR q768_scale * phi_argument f w total) /\
  interval_bounded z Q768FiniteBounds.log_hi
    (Q768FiniteBounds.log_width + 1).
Proof.
  intros f w total [Hf [Hw [Hwtotal Htotalmax]]].
  cbn zeta.
  assert (Htotal : (total <> 0)%N) by lia.
  set (l := certified_log_model f).
  assert (Hlcontains : interval_contains l
    (NR q768_scale * (- ln (1 - NR f / NR (2 ^ 64)%N)))).
  { unfold l. apply certified_log_model_contains. exact Hf. }
  assert (Hlbounded : interval_bounded l Q768FiniteBounds.log_hi
    Q768FiniteBounds.log_width).
  { unfold l. apply certified_log_model_bounded. exact (proj2 Hf). }
  split.
  - unfold phi_argument.
    replace
      (NR q768_scale *
        (NR w / NR total * - ln (1 - NR f / NR (2 ^ 64)%N)))
      with
      (NR q768_scale *
        (NR w / NR total * (- ln (1 - NR f / NR (2 ^ 64)%N))))
      by ring.
    apply stake_scaled_contains; assumption.
  - apply stake_scaled_bounded; assumption.
Qed.

(* Signed phi-recurrence correspondence.  The real quantities below are
   unscaled; interval endpoints and the signed accumulator are Q768 integers. *)
Definition phi_exact_term (k : nat) (x : R) : R :=
  x ^ k / factorial_R k.

Definition phi_previous_term (k : nat) (x : R) : R :=
  if Nat.eqb k 1%nat then x else phi_exact_term (k - 1) x.

Definition next_phi_term (k : nat) (zi term : interval) : interval :=
  if Nat.eqb k 1%nat then term
  else idivi (imul term zi) (N.of_nat k).

Definition next_phi_bound
    (k : nat) (x_hi term_hi term_width : N) : N * N :=
  if Nat.eqb k 1%nat then (term_hi, term_width)
  else
    let '(mul_hi, mul_width) :=
      Q768FiniteBounds.mul_bound term_hi x_hi term_width 0 in
    Q768FiniteBounds.div_scalar_bound mul_hi mul_width (N.of_nat k).

Definition next_phi_sum
    (lower : bool) (k : nat) (term : interval) (sum : Z) : Z :=
  let odd := Nat.odd k in
  let v := Z.of_N (selected_endpoint lower odd term) in
  if odd then (sum + v)%Z else (sum - v)%Z.

Definition phi_sum_sound
    (lower : bool) (sum : Z) (exact : R) (error : N) : Prop :=
  if lower then
    0 <= NR q768_scale * exact - IZR sum <= NR error
  else
    0 <= IZR sum - NR q768_scale * exact <= NR error.

Lemma factorial_R_positive : forall k : nat, 0 < factorial_R k.
Proof.
  induction k as [|k IH].
  - cbn [factorial_R]. lra.
  - cbn [factorial_R]. apply Rmult_lt_0_compat.
    + apply lt_0_INR. lia.
    + exact IH.
Qed.

Lemma phi_term_transition : forall k x,
  (1 <= k)%nat ->
  (if Nat.eqb k 1%nat then phi_previous_term k x
   else phi_previous_term k x * x / INR k) = phi_exact_term k x.
Proof.
  intros [|[|k]] x Hk; try lia.
  - rewrite Nat.eqb_refl. unfold phi_previous_term, phi_exact_term.
    rewrite Nat.eqb_refl. cbn [factorial_R].
    rewrite pow_1, INR_1, Rmult_1_r, Rdiv_1_r. reflexivity.
  - assert (Hnotone : Nat.eqb (S (S k)) 1%nat = false) by reflexivity.
    rewrite Hnotone. unfold phi_previous_term, phi_exact_term.
    rewrite Hnotone.
    replace (S (S k) - 1)%nat with (S k)%nat by lia.
    cbn [factorial_R pow].
    field.
    split.
    + apply Rgt_not_eq, factorial_R_positive.
    + split; apply not_0_INR; lia.
Qed.

Lemma phi_previous_term_succ : forall k x,
  (1 <= k)%nat ->
  phi_previous_term (S k) x = phi_exact_term k x.
Proof.
  intros [|k] x Hk; [lia |].
  cbn [phi_previous_term]. reflexivity.
Qed.

Lemma phi_partial_step : forall k x,
  (1 <= k)%nat ->
  phi_partial k x =
    if Nat.odd k then phi_partial (k - 1) x + phi_exact_term k x
    else phi_partial (k - 1) x - phi_exact_term k x.
Proof.
  intros [|k] x Hk; [lia |].
  cbn [phi_partial phi_exact_term].
  rewrite <- Nat.negb_odd.
  destruct (Nat.odd (S k)); unfold phi_exact_term; simpl;
    rewrite Nat.sub_0_r; reflexivity.
Qed.

Lemma next_phi_term_bounded : forall k zi term x_hi term_hi term_width,
  (1 <= k)%nat ->
  interval_bounded zi x_hi 0 ->
  interval_bounded term term_hi term_width ->
  interval_bounded (next_phi_term k zi term)
    (fst (next_phi_bound k x_hi term_hi term_width))
    (snd (next_phi_bound k x_hi term_hi term_width)).
Proof.
  intros k zi term x_hi term_hi term_width Hk Hzi Hterm.
  unfold next_phi_term, next_phi_bound.
  destruct (Nat.eqb k 1%nat) eqn:Hone; [exact Hterm |].
  assert (Hkn : (N.of_nat k <> 0)%N).
  { intro Heq. change (N.of_nat k = N.of_nat 0) in Heq.
    apply Nat2N.inj_iff in Heq. lia. }
  apply idivi_bounded; [exact Hkn |].
  apply imul_bounded; assumption.
Qed.

Lemma next_phi_term_contains : forall k zi term x,
  (1 <= k)%nat ->
  interval_contains zi (NR q768_scale * x) ->
  interval_contains term (NR q768_scale * phi_previous_term k x) ->
  interval_contains (next_phi_term k zi term)
    (NR q768_scale * phi_exact_term k x).
Proof.
  intros k zi term x Hk Hzi Hterm.
  unfold next_phi_term.
  destruct (Nat.eqb k 1%nat) eqn:Hone.
  - apply Nat.eqb_eq in Hone. subst k.
    pose proof (phi_term_transition 1%nat x (le_n 1%nat)) as Htransition.
    rewrite Nat.eqb_refl in Htransition.
    rewrite <- Htransition. exact Hterm.
  - assert (Hkn : (N.of_nat k <> 0)%N).
    { intro Heq. change (N.of_nat k = N.of_nat 0) in Heq.
      apply Nat2N.inj_iff in Heq. lia. }
    pose proof (imul_scaled_contains term zi
      (phi_previous_term k x) x Hterm Hzi) as Hmul.
    pose proof (idivi_scaled_contains (imul term zi)
      (phi_previous_term k x * x) (N.of_nat k) Hkn Hmul) as Hdiv.
    rewrite NR_of_nat in Hdiv.
    rewrite <- (phi_term_transition k x Hk).
    rewrite Hone. exact Hdiv.
Qed.

Lemma interval_rounding_errors : forall t exact upper width,
  interval_contains t exact ->
  interval_bounded t upper width ->
  (0 <= exact - NR t.(ilo) <= NR width) /\
  (0 <= NR t.(ihi) - exact <= NR width).
Proof.
  intros t exact upper width Hcontains Hbounded.
  destruct Hcontains as [Hlo Hhi].
  destruct Hbounded as [Hupper [Hwidth Horder]].
  assert (Hrealwidth : NR t.(ihi) - NR t.(ilo) <= NR width).
  {
    rewrite <- NR_sub by exact Horder.
    apply NR_le. exact Hwidth.
  }
  split; lra.
Qed.

Lemma phi_sum_sound_step : forall
    (lower odd : bool) (sum : Z) (exact_sum : R) (error : N)
    (t : interval) (exact_term : R) (upper width : N),
  phi_sum_sound lower sum exact_sum error ->
  interval_contains t (NR q768_scale * exact_term) ->
  interval_bounded t upper width ->
  phi_sum_sound lower
    (if odd then (sum + Z.of_N (selected_endpoint lower odd t))%Z
     else (sum - Z.of_N (selected_endpoint lower odd t))%Z)
    (if odd then exact_sum + exact_term else exact_sum - exact_term)
    (error + width).
Proof.
  intros lower odd sum exact_sum error t exact_term upper width
    Hsum Hcontains Hbounded.
  pose proof (interval_rounding_errors t
    (NR q768_scale * exact_term) upper width Hcontains Hbounded)
    as [Hlower Hupper].
  destruct lower, odd;
    cbn [phi_sum_sound selected_endpoint] in Hsum |- *;
    rewrite ?plus_IZR, ?minus_IZR, NR_add;
    fold (NR t.(ilo)) (NR t.(ihi)); nra.
Qed.

Lemma phi_recurrence_step : forall remaining k zi lower st,
  phi_recurrence (S remaining) k zi lower st =
  phi_recurrence remaining (S k) zi lower
    {| phi_term := next_phi_term k zi st.(phi_term);
       phi_sum := next_phi_sum lower k
         (next_phi_term k zi st.(phi_term)) st.(phi_sum) |}.
Proof.
  intros remaining k zi lower st.
  unfold next_phi_term, next_phi_sum. reflexivity.
Qed.

Lemma phi_terms_step : forall remaining k x_hi term_hi term_width error,
  Q768FiniteBounds.phi_terms (S remaining) k
    x_hi term_hi term_width error =
  Q768FiniteBounds.phi_terms remaining (S k) x_hi
    (fst (next_phi_bound k x_hi term_hi term_width))
    (snd (next_phi_bound k x_hi term_hi term_width))
    (error + snd (next_phi_bound k x_hi term_hi term_width)).
Proof.
  intros remaining k x_hi term_hi term_width error.
  unfold next_phi_bound. reflexivity.
Qed.

Lemma phi_recurrence_sound : forall
    remaining k zi lower st x x_hi term_hi term_width error,
  (1 <= k)%nat ->
  interval_bounded zi x_hi 0 ->
  interval_contains zi (NR q768_scale * x) ->
  interval_bounded st.(phi_term) term_hi term_width ->
  interval_contains st.(phi_term)
    (NR q768_scale * phi_previous_term k x) ->
  phi_sum_sound lower st.(phi_sum) (phi_partial (k - 1) x) error ->
  phi_sum_sound lower
    (phi_recurrence remaining k zi lower st).(phi_sum)
    (phi_partial (k - 1 + remaining) x)
    (Q768FiniteBounds.phi_terms remaining k
      x_hi term_hi term_width error).
Proof.
  induction remaining as [|remaining IH];
    intros k zi lower st x x_hi term_hi term_width error
      Hk Hzibounded Hzicontains Htermbounded Htermcontains Hsum.
  - cbn [phi_recurrence Q768FiniteBounds.phi_terms].
    rewrite Nat.add_0_r. exact Hsum.
  - rewrite phi_recurrence_step, phi_terms_step.
    set (current := next_phi_term k zi st.(phi_term)).
    set (current_bound := next_phi_bound k x_hi term_hi term_width).
    assert (Hcurrentbounded : interval_bounded current
      (fst current_bound) (snd current_bound)).
    {
      unfold current, current_bound.
      apply next_phi_term_bounded; assumption.
    }
    assert (Hcurrentcontains : interval_contains current
      (NR q768_scale * phi_exact_term k x)).
    {
      unfold current.
      apply next_phi_term_contains; assumption.
    }
    assert (Hnextsum : phi_sum_sound lower
      (next_phi_sum lower k current st.(phi_sum))
      (phi_partial k x) (error + snd current_bound)).
    {
      pose proof (phi_sum_sound_step lower (Nat.odd k) st.(phi_sum)
        (phi_partial (k - 1) x) error current (phi_exact_term k x)
        (fst current_bound) (snd current_bound)
        Hsum Hcurrentcontains Hcurrentbounded) as Hstep.
      unfold next_phi_sum.
      rewrite (phi_partial_step k x Hk). exact Hstep.
    }
    replace (k - 1 + S remaining)%nat with (S k - 1 + remaining)%nat
      by lia.
    apply IH with (x := x) (x_hi := x_hi)
      (term_hi := fst current_bound)
      (term_width := snd current_bound)
      (error := (error + snd current_bound)%N).
    + lia.
    + exact Hzibounded.
    + exact Hzicontains.
    + exact Hcurrentbounded.
    + rewrite phi_previous_term_succ by exact Hk.
      exact Hcurrentcontains.
    + replace (S k - 1)%nat with k by lia. exact Hnextsum.
Qed.

Definition phi_raw_sum (z : N) (terms : nat) (lower : bool) : Z :=
  let zi := {| ilo := z; ihi := z |} in
  (phi_recurrence terms 1%nat zi lower
    {| phi_term := zi; phi_sum := 0%Z |}).(phi_sum).

Lemma point_interval_bounded : forall z upper,
  (z <= upper)%N ->
  interval_bounded {| ilo := z; ihi := z |} upper 0.
Proof.
  intros z upper Hz. unfold interval_bounded; simpl. repeat split; lia.
Qed.

Lemma point_interval_contains_scaled : forall z,
  interval_contains {| ilo := z; ihi := z |}
    (NR q768_scale * (NR z / NR q768_scale)).
Proof.
  intro z.
  assert (HS : NR q768_scale <> 0) by
    (apply Rgt_not_eq, positive_NR; exact q768_nonzero).
  replace (NR q768_scale * (NR z / NR q768_scale)) with (NR z)
    by (field; exact HS).
  unfold interval_contains; simpl. split; apply Rle_refl.
Qed.

Lemma phi_raw_sum_sound : forall z terms lower,
  (z <= Q768FiniteBounds.log_hi)%N ->
  phi_sum_sound lower (phi_raw_sum z terms lower)
    (phi_partial terms (NR z / NR q768_scale))
    (Q768FiniteBounds.phi_rounding_width terms).
Proof.
  intros z terms lower Hz.
  set (zi := {| ilo := z; ihi := z |}).
  set (x := NR z / NR q768_scale).
  set (initial := {| phi_term := zi; phi_sum := 0%Z |}).
  assert (Hzibounded : interval_bounded zi Q768FiniteBounds.log_hi 0).
  { unfold zi. apply point_interval_bounded. exact Hz. }
  assert (Hzicontains : interval_contains zi (NR q768_scale * x)).
  { unfold zi, x. apply point_interval_contains_scaled. }
  assert (Hinitialterm : interval_contains initial.(phi_term)
    (NR q768_scale * phi_previous_term 1%nat x)).
  {
    unfold initial. simpl. unfold phi_previous_term. rewrite Nat.eqb_refl.
    exact Hzicontains.
  }
  assert (Hinitialsum : phi_sum_sound lower initial.(phi_sum)
    (phi_partial 0%nat x) 0).
  {
    unfold initial, phi_sum_sound. simpl.
    destruct lower; unfold NR; simpl; lra.
  }
  pose proof (phi_recurrence_sound terms 1%nat zi lower initial x
    Q768FiniteBounds.log_hi Q768FiniteBounds.log_hi 0 0
    (le_n 1%nat) Hzibounded Hzicontains Hzibounded Hinitialterm Hinitialsum)
    as Hsound.
  unfold Q768FiniteBounds.phi_rounding_width.
  replace (1 - 1 + terms)%nat with terms in Hsound by lia.
  unfold phi_raw_sum. fold zi initial. exact Hsound.
Qed.

Lemma NR_pow : forall a : N, forall n : nat,
  NR (a ^ (N.of_nat n)) = NR a ^ n.
Proof.
  intros a n. induction n as [|n IH].
  - simpl. unfold NR. simpl. reflexivity.
  - rewrite Nat2N.inj_succ, N.pow_succ_r'.
    rewrite NR_mul, IH. simpl. ring.
Qed.

Lemma NR_pow_N : forall a n : N,
  NR (a ^ n) = NR a ^ N.to_nat n.
Proof.
  intros a n. induction n using N.peano_ind.
  - simpl. unfold NR. simpl. reflexivity.
  - rewrite N.pow_succ_r', NR_mul, N2Nat.inj_succ, IHn.
    simpl. ring.
Qed.

Lemma finite_factorial_eq_nat_factorial : forall n : nat,
  Q768FiniteBounds.factorial n = N.of_nat (fact n).
Proof.
  induction n as [|n IH].
  - reflexivity.
  - cbn [Q768FiniteBounds.factorial fact].
    rewrite IH, <- Nat2N.inj_mul. reflexivity.
Qed.

Lemma NR_finite_factorial : forall n : nat,
  NR (Q768FiniteBounds.factorial n) = factorial_R n.
Proof.
  intro n. rewrite finite_factorial_eq_nat_factorial, NR_of_nat.
  symmetry. apply factorial_R_eq_INR_fact.
Qed.

Lemma phi_endpoint_domain : forall z,
  (0 < z <= Q768FiniteBounds.log_hi)%N ->
  0 < NR z / NR q768_scale < 7 / 10.
Proof.
  intros z [Hzpos Hzhi].
  assert (HS : 0 < NR q768_scale) by
    (apply positive_NR; exact q768_nonzero).
  assert (HzRpos : 0 < NR z) by
    (change (NR 0 < NR z); apply NR_lt; exact Hzpos).
  assert (HzRhi : NR z <= NR Q768FiniteBounds.log_hi) by
    (apply NR_le; exact Hzhi).
  pose proof Q768FiniteBounds.certified_log_upper_is_below_seven_tenths
    as Hfinite.
  apply NR_lt in Hfinite.
  repeat rewrite NR_mul in Hfinite.
  replace (NR 10) with (10 : R) in Hfinite by
    (unfold NR; simpl; ring).
  replace (NR 7) with (7 : R) in Hfinite by
    (unfold NR; simpl; ring).
  change (NR Q768FiniteBounds.q768_scale) with (NR q768_scale) in Hfinite.
  split.
  - apply Rdiv_lt_0_compat; assumption.
  - apply (Rmult_lt_reg_r (NR q768_scale)); [exact HS |].
    replace (NR z / NR q768_scale * NR q768_scale) with (NR z)
      by (field; lra).
    apply (Rmult_lt_reg_r 10); [lra |].
    replace (7 / 10 * NR q768_scale * 10)
      with (7 * NR q768_scale) by field.
    nra.
Qed.

Lemma exp_tail_129_scaled_lt_one :
  NR q768_scale * ((7 / 10) ^ 129 / factorial_R 129%nat) < 1.
Proof.
  pose proof Q768FiniteBounds.exp_tail_129_is_below_one_q768_unit
    as Hfinite.
  apply NR_lt in Hfinite.
  repeat rewrite NR_mul in Hfinite.
  replace (NR (7 ^ 129)%N) with ((NR 7) ^ 129) in Hfinite.
  2: { rewrite NR_pow_N. reflexivity. }
  replace (NR (10 ^ 129)%N) with ((NR 10) ^ 129) in Hfinite.
  2: { rewrite NR_pow_N. reflexivity. }
  rewrite NR_finite_factorial in Hfinite.
  replace (NR 7) with (7 : R) in Hfinite by
    (unfold NR; simpl; ring).
  replace (NR 10) with (10 : R) in Hfinite by
    (unfold NR; simpl; ring).
  change (NR Q768FiniteBounds.q768_scale) with (NR q768_scale) in Hfinite.
  assert (Hfact : 0 < factorial_R 129%nat) by apply factorial_R_positive.
  assert (Hten : 0 < (10 : R) ^ 129) by (apply pow_lt; lra).
  replace (NR q768_scale * ((7 / 10) ^ 129 / factorial_R 129%nat))
    with
    ((NR q768_scale * 7 ^ 129) /
      (10 ^ 129 * factorial_R 129%nat)).
  2: { field; nra. }
  apply (Rmult_lt_reg_r (10 ^ 129 * factorial_R 129%nat)); [nra |].
  replace
    ((NR q768_scale * 7 ^ 129 /
      (10 ^ 129 * factorial_R 129%nat)) *
      (10 ^ 129 * factorial_R 129%nat))
    with (NR q768_scale * 7 ^ 129) by (field; nra).
  nra.
Qed.

Lemma exp_tail_130_scaled_lt_one :
  NR q768_scale * ((7 / 10) ^ 130 / factorial_R 130%nat) < 1.
Proof.
  pose proof Q768FiniteBounds.exp_tail_130_is_below_one_q768_unit
    as Hfinite.
  apply NR_lt in Hfinite.
  repeat rewrite NR_mul in Hfinite.
  replace (NR (7 ^ 130)%N) with ((NR 7) ^ 130) in Hfinite.
  2: { rewrite NR_pow_N. reflexivity. }
  replace (NR (10 ^ 130)%N) with ((NR 10) ^ 130) in Hfinite.
  2: { rewrite NR_pow_N. reflexivity. }
  rewrite NR_finite_factorial in Hfinite.
  replace (NR 7) with (7 : R) in Hfinite by
    (unfold NR; simpl; ring).
  replace (NR 10) with (10 : R) in Hfinite by
    (unfold NR; simpl; ring).
  change (NR Q768FiniteBounds.q768_scale) with (NR q768_scale) in Hfinite.
  assert (Hfact : 0 < factorial_R 130%nat) by apply factorial_R_positive.
  assert (Hten : 0 < (10 : R) ^ 130) by (apply pow_lt; lra).
  replace (NR q768_scale * ((7 / 10) ^ 130 / factorial_R 130%nat))
    with
    ((NR q768_scale * 7 ^ 130) /
      (10 ^ 130 * factorial_R 130%nat)).
  2: { field; nra. }
  apply (Rmult_lt_reg_r (10 ^ 130 * factorial_R 130%nat)); [nra |].
  replace
    ((NR q768_scale * 7 ^ 130 /
      (10 ^ 130 * factorial_R 130%nat)) *
      (10 ^ 130 * factorial_R 130%nat))
    with (NR q768_scale * 7 ^ 130) by (field; nra).
  nra.
Qed.

Lemma true_phi_positive : forall x, 0 < x -> 0 < true_phi x.
Proof.
  intros x Hx. unfold true_phi.
  pose proof (exp_increasing (-x) 0) as Hexp.
  rewrite exp_0 in Hexp. lra.
Qed.

Lemma scaled_phi_remainders_lt_one : forall x,
  0 < x < 7 / 10 ->
  NR q768_scale * (true_phi x - phi_partial 128%nat x) < 1 /\
  NR q768_scale * (phi_partial 129%nat x - true_phi x) < 1.
Proof.
  intros x Hdomain.
  pose proof (phi_bracket_at_exactly_128_and_129_terms x Hdomain)
    as Hanalytic.
  destruct Hanalytic as [Hbracket [Hlower Hupper]].
  assert (Hfact129 : 0 < factorial_R 129%nat) by apply factorial_R_positive.
  assert (Hfact130 : 0 < factorial_R 130%nat) by apply factorial_R_positive.
  assert (Hpow129 : x ^ 129 <= (7 / 10) ^ 129).
  { apply pow_incr. lra. }
  assert (Hpow130 : x ^ 130 <= (7 / 10) ^ 130).
  { apply pow_incr. lra. }
  assert (Hterm129 :
    x ^ 129 / factorial_R 129%nat <=
      (7 / 10) ^ 129 / factorial_R 129%nat).
  {
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat. exact Hfact129.
    - exact Hpow129.
  }
  assert (Hterm130 :
    x ^ 130 / factorial_R 130%nat <=
      (7 / 10) ^ 130 / factorial_R 130%nat).
  {
    unfold Rdiv. apply Rmult_le_compat_r.
    - apply Rlt_le, Rinv_0_lt_compat. exact Hfact130.
    - exact Hpow130.
  }
  assert (HS : 0 < NR q768_scale) by
    (apply positive_NR; exact q768_nonzero).
  split.
  - eapply Rlt_trans.
    + apply Rmult_lt_compat_l; [exact HS | exact Hlower].
    + eapply Rle_lt_trans.
      * apply Rmult_le_compat_l; [lra | exact Hterm129].
      * exact exp_tail_129_scaled_lt_one.
  - eapply Rlt_trans.
    + apply Rmult_lt_compat_l; [exact HS | exact Hupper].
    + eapply Rle_lt_trans.
      * apply Rmult_le_compat_l; [lra | exact Hterm130].
      * exact exp_tail_130_scaled_lt_one.
Qed.

Lemma phi_lower_raw_error : forall z,
  (0 < z <= Q768FiniteBounds.log_hi)%N ->
  let x := NR z / NR q768_scale in
  0 <= NR q768_scale * true_phi x -
    IZR (phi_raw_sum z 128%nat true) /\
  NR q768_scale * true_phi x -
    IZR (phi_raw_sum z 128%nat true) < 255.
Proof.
  intros z Hz. cbn zeta.
  set (x := NR z / NR q768_scale).
  pose proof (phi_endpoint_domain z Hz) as Hdomain.
  fold x in Hdomain.
  pose proof (phi_raw_sum_sound z 128%nat true (proj2 Hz)) as Hsound.
  fold x in Hsound.
  cbn [phi_sum_sound] in Hsound.
  rewrite Q768FiniteBounds.phi_128_rounding_width_is_254 in Hsound.
  replace (NR 254) with (254 : R) in Hsound by
    (unfold NR; simpl; ring).
  pose proof (phi_bracket_at_exactly_128_and_129_terms x Hdomain)
    as Hanalytic.
  pose proof (scaled_phi_remainders_lt_one x Hdomain) as Htails.
  change (0 <= NR q768_scale * true_phi x -
    IZR (phi_raw_sum z 128%nat true) /\
    NR q768_scale * true_phi x -
    IZR (phi_raw_sum z 128%nat true) < 255).
  destruct Hanalytic as [Hbracket _].
  destruct Htails as [Htail _].
  assert (HS0 : 0 <= NR q768_scale) by apply NR_nonnegative.
  assert (Hscaledbracket :
    NR q768_scale * phi_partial 128%nat x <=
      NR q768_scale * true_phi x).
  { apply Rmult_le_compat_l; [exact HS0 | exact (proj1 Hbracket)]. }
  assert (Hdecompose :
    NR q768_scale * true_phi x - IZR (phi_raw_sum z 128%nat true) =
    NR q768_scale * (true_phi x - phi_partial 128%nat x) +
      (NR q768_scale * phi_partial 128%nat x -
        IZR (phi_raw_sum z 128%nat true))) by lra.
  split.
  - pose proof (proj1 Hsound). lra.
  - rewrite Hdecompose. pose proof (proj2 Hsound). lra.
Qed.

Lemma phi_upper_raw_error : forall z,
  (0 < z <= Q768FiniteBounds.log_hi)%N ->
  let x := NR z / NR q768_scale in
  0 <= IZR (phi_raw_sum z 129%nat false) - NR q768_scale * true_phi x /\
  IZR (phi_raw_sum z 129%nat false) - NR q768_scale * true_phi x < 257.
Proof.
  intros z Hz. cbn zeta.
  set (x := NR z / NR q768_scale).
  pose proof (phi_endpoint_domain z Hz) as Hdomain.
  fold x in Hdomain.
  pose proof (phi_raw_sum_sound z 129%nat false (proj2 Hz)) as Hsound.
  fold x in Hsound.
  cbn [phi_sum_sound] in Hsound.
  rewrite Q768FiniteBounds.phi_129_rounding_width_is_256 in Hsound.
  replace (NR 256) with (256 : R) in Hsound by
    (unfold NR; simpl; ring).
  pose proof (phi_bracket_at_exactly_128_and_129_terms x Hdomain)
    as Hanalytic.
  pose proof (scaled_phi_remainders_lt_one x Hdomain) as Htails.
  destruct Hanalytic as [Hbracket _].
  destruct Htails as [_ Htail].
  assert (HS0 : 0 <= NR q768_scale) by apply NR_nonnegative.
  assert (Hscaledbracket :
    NR q768_scale * true_phi x <=
      NR q768_scale * phi_partial 129%nat x).
  { apply Rmult_le_compat_l; [exact HS0 | exact (proj2 Hbracket)]. }
  assert (Hdecompose :
    IZR (phi_raw_sum z 129%nat false) - NR q768_scale * true_phi x =
    (IZR (phi_raw_sum z 129%nat false) -
      NR q768_scale * phi_partial 129%nat x) +
    NR q768_scale * (phi_partial 129%nat x - true_phi x)) by lra.
  split.
  - pose proof (proj1 Hsound). lra.
  - rewrite Hdecompose. pose proof (proj2 Hsound). lra.
Qed.

Lemma phi_model_as_raw_sum : forall z terms lower,
  phi_model z terms lower = Z.to_N (phi_raw_sum z terms lower).
Proof. reflexivity. Qed.

Lemma NR_Z_to_N_nonnegative : forall sum : Z,
  (0 <= sum)%Z -> NR (Z.to_N sum) = IZR sum.
Proof.
  intros sum Hsum. unfold NR. rewrite Z2N.id by exact Hsum. reflexivity.
Qed.

Lemma Z_to_N_negative : forall sum : Z,
  (sum < 0)%Z -> Z.to_N sum = 0%N.
Proof.
  intros [|p|p] Hsum; simpl; lia.
Qed.

Lemma IZR_negative : forall sum : Z,
  (sum < 0)%Z -> IZR sum < 0.
Proof.
  intros sum Hsum. change (IZR sum < IZR 0).
  apply IZR_lt. exact Hsum.
Qed.

Lemma lower_Z_to_N_preserves_error : forall sum exact budget,
  0 <= exact ->
  0 <= exact - IZR sum /\ exact - IZR sum < budget ->
  0 <= exact - NR (Z.to_N sum) /\
    exact - NR (Z.to_N sum) < budget.
Proof.
  intros sum exact budget Hexact Herror.
  destruct (Z_lt_ge_dec sum 0) as [Hneg | Hnonneg].
  - rewrite Z_to_N_negative by exact Hneg.
    replace (NR 0) with (0 : R) by (unfold NR; simpl; reflexivity).
    pose proof (IZR_negative sum Hneg). lra.
  - assert (H0 : (0 <= sum)%Z) by lia.
    rewrite NR_Z_to_N_nonnegative by exact H0. exact Herror.
Qed.

Lemma upper_Z_to_N_preserves_error : forall sum exact budget,
  0 <= exact ->
  0 <= IZR sum - exact /\ IZR sum - exact < budget ->
  0 <= NR (Z.to_N sum) - exact /\
    NR (Z.to_N sum) - exact < budget.
Proof.
  intros sum exact budget Hexact Herror.
  assert (Hnonneg : (0 <= sum)%Z).
  {
    destruct (Z_lt_ge_dec sum 0) as [Hneg | Hnonneg]; [|lia].
    pose proof (IZR_negative sum Hneg). lra.
  }
  rewrite NR_Z_to_N_nonnegative by exact Hnonneg. exact Herror.
Qed.

Lemma phi_lower_model_error : forall z,
  (0 < z <= Q768FiniteBounds.log_hi)%N ->
  let x := NR z / NR q768_scale in
  0 <= NR q768_scale * true_phi x - NR (phi_model z 128%nat true) /\
  NR q768_scale * true_phi x - NR (phi_model z 128%nat true) < 255.
Proof.
  intros z Hz. cbn zeta.
  set (x := NR z / NR q768_scale).
  pose proof (phi_endpoint_domain z Hz) as Hdomain. fold x in Hdomain.
  pose proof (phi_lower_raw_error z Hz) as Hraw. fold x in Hraw.
  rewrite phi_model_as_raw_sum.
  apply lower_Z_to_N_preserves_error.
  - pose proof (true_phi_positive x (proj1 Hdomain)).
    pose proof (positive_NR q768_scale q768_nonzero). nra.
  - exact Hraw.
Qed.

Lemma phi_upper_model_error : forall z,
  (0 < z <= Q768FiniteBounds.log_hi)%N ->
  let x := NR z / NR q768_scale in
  0 <= NR (phi_model z 129%nat false) - NR q768_scale * true_phi x /\
  NR (phi_model z 129%nat false) - NR q768_scale * true_phi x < 257.
Proof.
  intros z Hz. cbn zeta.
  set (x := NR z / NR q768_scale).
  pose proof (phi_endpoint_domain z Hz) as Hdomain. fold x in Hdomain.
  pose proof (phi_upper_raw_error z Hz) as Hraw. fold x in Hraw.
  rewrite phi_model_as_raw_sum.
  apply upper_Z_to_N_preserves_error.
  - pose proof (true_phi_positive x (proj1 Hdomain)).
    pose proof (positive_NR q768_scale q768_nonzero). nra.
  - exact Hraw.
Qed.

Lemma log_recurrence_sum_monotone : forall remaining n y2 st,
  (st.(log_sum).(ilo) <=
    (log_recurrence remaining n y2 st).(log_sum).(ilo))%N.
Proof.
  induction remaining as [|remaining IH]; intros n y2 st.
  - apply N.le_refl.
  - cbn [log_recurrence]. destruct remaining as [|remaining'].
    + simpl. apply N.le_add_r.
    + apply (N.le_trans _
        (st.(log_sum).(ilo) +
          (idivi st.(log_power) (N.of_nat (2 * n + 1))).(ilo))%N).
      * simpl. apply N.le_add_r.
      * pose proof (IH (Nat.succ n) y2
          {| log_power := imul st.(log_power) y2;
             log_sum :=
               {| ilo := st.(log_sum).(ilo) +
                    (idivi st.(log_power)
                      (N.of_nat (2 * n + 1))).(ilo);
                  ihi := st.(log_sum).(ihi) +
                    (idivi st.(log_power)
                      (N.of_nat (2 * n + 1))).(ihi) |} |}) as Hrec.
        exact Hrec.
Qed.

Lemma log_recurrence_first_term_lower : forall remaining n y2 st,
  (st.(log_sum).(ilo) +
      st.(log_power).(ilo) / N.of_nat (2 * n + 1) <=
    (log_recurrence (S remaining) n y2 st).(log_sum).(ilo))%N.
Proof.
  intros [|remaining] n y2 st.
  - cbn [log_recurrence]. apply N.le_refl.
  - change
      (st.(log_sum).(ilo) +
          st.(log_power).(ilo) / N.of_nat (2 * n + 1) <=
       (log_recurrence (S remaining) (Nat.succ n) y2
          {| log_power := imul st.(log_power) y2;
             log_sum :=
               {| ilo := st.(log_sum).(ilo) +
                    st.(log_power).(ilo) / N.of_nat (2 * n + 1);
                  ihi := st.(log_sum).(ihi) +
                    ceil_div st.(log_power).(ihi)
                      (N.of_nat (2 * n + 1)) |} |}).(log_sum).(ilo))%N.
    exact (log_recurrence_sum_monotone (S remaining) (Nat.succ n) y2
      {| log_power := imul st.(log_power) y2;
         log_sum :=
           {| ilo := st.(log_sum).(ilo) +
                st.(log_power).(ilo) / N.of_nat (2 * n + 1);
              ihi := st.(log_sum).(ihi) +
                ceil_div st.(log_power).(ihi)
                  (N.of_nat (2 * n + 1)) |} |}).
Qed.

Lemma certified_log_model_lower_bound : forall f,
  (1 <= f <= 2 ^ 63)%N ->
  (2 ^ 704 <= (certified_log_model f).(ilo))%N.
Proof.
  intros f [Hfpos Hfmax].
  unfold certified_log_model.
  set (fq := (f * 2 ^ (768 - 64))%N).
  set (den := (2 * q768_scale - fq)%N).
  set (y := {| ilo := (fq * q768_scale) / den;
               ihi := ceil_div (fq * q768_scale) den |}).
  set (y2 := imul y y).
  set (initial := {| log_power := y;
                     log_sum := {| ilo := 0; ihi := 0 |} |}).
  set (final := log_recurrence 256%nat 0%nat y2 initial).
  assert (Hfqlo : (2 ^ 704 <= fq)%N).
  {
    unfold fq.
    replace (2 ^ 704)%N with (1 * 2 ^ (768 - 64))%N by
      (vm_compute; reflexivity).
    apply N.mul_le_mono_r. exact Hfpos.
  }
  assert (Hfqhi : (2 * fq <= q768_scale)%N).
  {
    unfold fq. pose proof (N.mul_le_mono_r f (2 ^ 63)
      (2 ^ (768 - 64)) Hfmax) as Hmul.
    rewrite <- q768_shift_identity. nia.
  }
  assert (Hden : (den <> 0)%N).
  { unfold den. pose proof q768_nonzero. nia. }
  assert (Hdenle : (den <= 2 * q768_scale)%N).
  { unfold den. nia. }
  assert (Hidentity :
    ((2 * q768_scale) * 2 ^ 703 = (2 ^ 704) * q768_scale)%N).
  { unfold q768_scale. vm_compute. reflexivity. }
  assert (Hnumer : (den * 2 ^ 703 <= fq * q768_scale)%N).
  {
    eapply N.le_trans.
    - apply N.mul_le_mono_r. exact Hdenle.
    - rewrite Hidentity. apply N.mul_le_mono_r. exact Hfqlo.
  }
  assert (Hylo : (2 ^ 703 <= y.(ilo))%N).
  {
    unfold y. simpl. apply N.div_le_lower_bound; assumption.
  }
  pose proof (log_recurrence_first_term_lower 255%nat 0%nat y2 initial)
    as Hfirst.
  fold final in Hfirst.
  cbn [initial] in Hfirst.
  rewrite N.div_1_r in Hfirst.
  assert (Hdouble : (2 ^ 704 = 2 * 2 ^ 703)%N) by
    (vm_compute; reflexivity).
  rewrite Hdouble. apply N.mul_le_mono_l.
  eapply N.le_trans; eauto.
Qed.

Lemma stake_lower_endpoint_bound : forall f w total,
  admissible f w total ->
  let l := certified_log_model f in
  (2 ^ 640 <= (l.(ilo) * w) / total)%N.
Proof.
  intros f w total [Hf [Hw [Hwtotal Htotalmax]]]. cbn zeta.
  assert (Htotal : (total <> 0)%N) by lia.
  pose proof (certified_log_model_lower_bound f Hf) as Hlog.
  apply N.div_le_lower_bound; [exact Htotal |].
  assert (Htotal64 : (total <= 2 ^ 64)%N).
  {
    assert (Hstep : (2 ^ 64 - 1 <= 2 ^ 64)%N) by
      apply N.le_sub_l.
    exact (N.le_trans _ _ _ Htotalmax Hstep).
  }
  assert (Hleft : (total * 2 ^ 640 <= (2 ^ 64) * 2 ^ 640)%N).
  { apply N.mul_le_mono_r. exact Htotal64. }
  assert (Hidentity : ((2 ^ 64) * 2 ^ 640 = 2 ^ 704)%N) by
    (vm_compute; reflexivity).
  assert (Hright : (2 ^ 704 <= (certified_log_model f).(ilo) * w)%N).
  {
    eapply N.le_trans; [exact Hlog |].
    replace ((certified_log_model f).(ilo)) with
      ((certified_log_model f).(ilo) * 1)%N at 1 by lia.
    apply N.mul_le_mono_l. exact Hw.
  }
  rewrite Hidentity in Hleft. eapply N.le_trans; eauto.
Qed.

Lemma true_phi_monotone_lipschitz : forall a b,
  0 <= a <= b ->
  0 <= true_phi b - true_phi a <= b - a.
Proof.
  intros a b [Ha Hab].
  set (d := b - a).
  assert (Hd : 0 <= d) by (unfold d; lra).
  assert (Hed : 0 < exp (-d) <= 1).
  {
    split; [apply exp_pos |].
    destruct (Req_dec d 0) as [-> | Hdn].
    - rewrite Ropp_0, exp_0. lra.
    - pose proof (exp_increasing (-d) 0) as Hinc.
      rewrite exp_0 in Hinc. lra.
  }
  assert (Hea : 0 < exp (-a) <= 1).
  {
    split; [apply exp_pos |].
    destruct (Req_dec a 0) as [-> | Han].
    - rewrite Ropp_0, exp_0. lra.
    - pose proof (exp_increasing (-a) 0) as Hinc.
      rewrite exp_0 in Hinc. lra.
  }
  pose proof (exp_ineq1_le (-d)) as Hlinear.
  assert (Hfactor : 0 <= 1 - exp (-d) <= d) by lra.
  assert (Hsplit : exp (-b) = exp (-a) * exp (-d)).
  {
    rewrite <- exp_plus. f_equal. unfold d. ring.
  }
  unfold true_phi. rewrite Hsplit. nra.
Qed.

Lemma scaled_true_phi_endpoint_gap : forall zlo zhi,
  (zlo <= zhi)%N ->
  0 <= NR q768_scale *
      (true_phi (NR zhi / NR q768_scale) -
       true_phi (NR zlo / NR q768_scale)) <=
    NR (zhi - zlo).
Proof.
  intros zlo zhi Horder.
  assert (HS : 0 < NR q768_scale) by
    apply positive_NR, q768_nonzero.
  assert (Hzorder : NR zlo <= NR zhi).
  { apply NR_le. exact Horder. }
  pose proof (true_phi_monotone_lipschitz
    (NR zlo / NR q768_scale) (NR zhi / NR q768_scale)) as Hlip.
  assert (Hdomain :
    0 <= NR zlo / NR q768_scale <= NR zhi / NR q768_scale).
  {
    assert (Hinv : 0 < / NR q768_scale) by
      (apply Rinv_0_lt_compat; lra).
    split.
    - unfold Rdiv. apply Rmult_le_pos;
        [apply NR_nonnegative | left; exact Hinv].
    - unfold Rdiv. apply Rmult_le_compat_r; [lra | exact Hzorder].
  }
  specialize (Hlip Hdomain).
  assert (Hscaled :
    NR q768_scale *
      (NR zhi / NR q768_scale - NR zlo / NR q768_scale) =
    NR (zhi - zlo)).
  {
    rewrite NR_sub by exact Horder.
    field. lra.
  }
  nra.
Qed.

Lemma true_phi_unit_interval : forall x,
  0 <= x -> 0 <= true_phi x < 1.
Proof.
  intros x Hx.
  pose proof (true_phi_monotone_lipschitz 0 x) as Hmono.
  assert (Hzero : true_phi 0 = 0).
  { unfold true_phi. rewrite Ropp_0, exp_0. ring. }
  specialize (Hmono (conj (Rle_refl 0) Hx)).
  pose proof (exp_pos (-x)). unfold true_phi in *. rewrite Hzero in Hmono.
  lra.
Qed.

Lemma lower_q768_clamp_identity : forall p exact,
  NR p <= NR q768_scale * exact ->
  exact < 1 ->
  N.min q768_scale p = p.
Proof.
  intros p exact Hbelow Hunit.
  destruct (N.le_ge_cases p q768_scale) as [Hps | Hsp].
  - apply N.min_r. exact Hps.
  - destruct (N.eq_dec p q768_scale) as [-> | Hneq].
    + apply N.min_id.
    + assert (Hstrict : (q768_scale < p)%N) by lia.
      pose proof (NR_lt q768_scale p Hstrict).
      pose proof (positive_NR q768_scale q768_nonzero). nra.
Qed.

Lemma upper_q768_clamp_preserves : forall p exact,
  exact <= 1 ->
  NR q768_scale * exact <= NR p ->
  NR q768_scale * exact <= NR (N.min q768_scale p) <= NR p.
Proof.
  intros p exact Hunit Habove.
  destruct (N.le_ge_cases p q768_scale) as [Hps | Hsp].
  - rewrite N.min_r by exact Hps. split; [exact Habove | lra].
  - rewrite N.min_l by exact Hsp. split.
    + pose proof (positive_NR q768_scale q768_nonzero). nra.
    + apply NR_le. exact Hsp.
Qed.

Lemma NR_reflect_le : forall a b : N, NR a <= NR b -> (a <= b)%N.
Proof.
  intros a b Hab. unfold NR in Hab. apply N2Z.inj_le. now apply le_IZR.
Qed.

Lemma NR_reflect_lt : forall a b : N, NR a < NR b -> (a < b)%N.
Proof.
  intros a b Hab. unfold NR in Hab. apply N2Z.inj_lt. now apply lt_IZR.
Qed.

Lemma certificate_model_shape : forall f w total,
  certificate_model f w total =
    let l := certified_log_model f in
    let zlo := ((l.(ilo) * w) / total)%N in
    let zhi := ceil_div (l.(ihi) * w) total in
    (N.min q768_scale (phi_model zlo 128%nat true),
     N.min q768_scale (phi_model zhi 129%nat false)).
Proof. reflexivity. Qed.

Lemma full_q768_abstract_assembly :
  forall f w total zlo zhi pl ph lo hi : N,
    admissible f w total ->
    interval_contains {| ilo := zlo; ihi := zhi |}
      (NR q768_scale * phi_argument f w total) /\
    interval_bounded {| ilo := zlo; ihi := zhi |}
      Q768FiniteBounds.log_hi (Q768FiniteBounds.log_width + 1) ->
    (2 ^ 640 <= zlo)%N ->
    pl = phi_model zlo 128%nat true ->
    ph = phi_model zhi 129%nat false ->
    lo = N.min q768_scale pl ->
    hi = N.min q768_scale ph ->
    (NR lo / NR q768_scale <= true_probability f w total <= NR hi / NR q768_scale) /\
    (hi - lo <= 1537)%N /\
    (0 <= true_probability f w total - NR lo / NR q768_scale
      < NR 1281 / NR q768_scale).
Proof.
  intros f w total zlo zhi pl ph lo hi Hadmissible Hbridge
    Hzlo_floor Hpl_def Hph_def Hlo_def Hhi_def.
  assert (HS : 0 < NR q768_scale) by
    apply positive_NR, q768_nonzero.
  cbv beta iota zeta delta [interval_contains interval_bounded] in Hbridge.
  destruct Hbridge as
    [[Hzlo_arg Harg_zhi] [Hzhi_upper [Hzwidth Hzorder]]].
  assert (Hzlo_upper : (zlo <= Q768FiniteBounds.log_hi)%N).
  { exact (N.le_trans zlo zhi Q768FiniteBounds.log_hi
      Hzorder Hzhi_upper). }
  assert (Hzlo_pos : (0 < zlo)%N).
  { eapply N.lt_le_trans; [|exact Hzlo_floor]. vm_compute. reflexivity. }
  assert (Hzhi_pos : (0 < zhi)%N).
  { exact (N.lt_le_trans 0 zlo zhi Hzlo_pos Hzorder). }
  assert (Hzwidth1026 : (zhi - zlo <= 1026)%N).
  {
    rewrite Q768FiniteBounds.certified_log_width_is_1025 in Hzwidth.
    exact Hzwidth.
  }

  set (xlo := NR zlo / NR q768_scale).
  set (xhi := NR zhi / NR q768_scale).
  set (x := phi_argument f w total).
  set (tp := true_probability f w total).
  set (glo := true_phi xlo).
  set (ghi := true_phi xhi).
  assert (HxloS : xlo * NR q768_scale = NR zlo).
  { unfold xlo. field. lra. }
  assert (HxhiS : xhi * NR q768_scale = NR zhi).
  { unfold xhi. field. lra. }
  assert (Hxrange : xlo <= x <= xhi).
  {
    split.
    - apply (Rmult_le_reg_r (NR q768_scale)); [exact HS |].
      rewrite HxloS. replace (x * NR q768_scale)
        with (NR q768_scale * x) by ring. exact Hzlo_arg.
    - apply (Rmult_le_reg_r (NR q768_scale)); [exact HS |].
      rewrite HxhiS. replace (x * NR q768_scale)
        with (NR q768_scale * x) by ring. exact Harg_zhi.
  }
  assert (Hxlo_nonneg : 0 <= xlo).
  {
    unfold xlo, Rdiv. apply Rmult_le_pos;
      [apply NR_nonnegative | left; apply Rinv_0_lt_compat; exact HS].
  }
  assert (Hx_nonneg : 0 <= x) by lra.
  assert (Hxhi_nonneg : 0 <= xhi) by lra.
  assert (Htp_phi : tp = true_phi x).
  { unfold tp, true_probability, true_phi, x. reflexivity. }
  pose proof (true_phi_monotone_lipschitz xlo x
    (conj Hxlo_nonneg (proj1 Hxrange))) as Hmono_lo.
  pose proof (true_phi_monotone_lipschitz x xhi
    (conj Hx_nonneg (proj2 Hxrange))) as Hmono_hi.
  fold glo ghi in Hmono_lo, Hmono_hi.
  rewrite <- Htp_phi in Hmono_lo, Hmono_hi.
  pose proof (true_phi_unit_interval x Hx_nonneg) as Htp_unit.
  rewrite <- Htp_phi in Htp_unit.

  pose proof (phi_lower_model_error zlo
    (conj Hzlo_pos Hzlo_upper)) as Hpl.
  cbv beta iota zeta in Hpl.
  rewrite <- Hpl_def in Hpl.
  change (0 <= NR q768_scale * glo - NR pl /\
          NR q768_scale * glo - NR pl < 255) in Hpl.
  pose proof (phi_upper_model_error zhi
    (conj Hzhi_pos Hzhi_upper)) as Hph.
  cbv beta iota zeta in Hph.
  rewrite <- Hph_def in Hph.
  change (0 <= NR ph - NR q768_scale * ghi /\
          NR ph - NR q768_scale * ghi < 257) in Hph.
  pose proof (scaled_true_phi_endpoint_gap zlo zhi Hzorder) as Hgap.
  change (0 <= NR q768_scale * (ghi - glo) <=
          NR (zhi - zlo)) in Hgap.
  assert (Hraw_bracket :
    NR pl <= NR q768_scale * tp <= NR ph) by nra.
  assert (Hlo_id : lo = pl).
  {
    rewrite Hlo_def. apply lower_q768_clamp_identity with (exact := tp);
      [exact (proj1 Hraw_bracket) | exact (proj2 Htp_unit)].
  }
  pose proof (upper_q768_clamp_preserves ph tp
    (Rlt_le _ _ (proj2 Htp_unit)) (proj2 Hraw_bracket)) as Hhi_clamp.
  rewrite <- Hhi_def in Hhi_clamp.
  assert (Hscaled_bracket :
    NR lo <= NR q768_scale * tp <= NR hi).
  { rewrite Hlo_id. split; [exact (proj1 Hraw_bracket) | exact (proj1 Hhi_clamp)]. }

  assert (HzgapR : NR (zhi - zlo) <= 1026).
  {
    pose proof (NR_le (zhi - zlo) 1026 Hzwidth1026) as H.
    replace (NR 1026) with (1026 : R) in H by
      (unfold NR; simpl; ring). exact H.
  }
  assert (Hraw_width : NR ph - NR pl < 1538) by nra.
  assert (Hclamped_width : NR hi - NR lo < 1538).
  { rewrite Hlo_id. nra. }
  assert (Hlohi : (lo <= hi)%N).
  { apply NR_reflect_le. nra. }
  assert (HwidthN : (hi - lo <= 1537)%N).
  {
    assert (HwidthR : NR (hi - lo) < NR 1538).
    {
      rewrite NR_sub by exact Hlohi.
      replace (NR 1538) with (1538 : R) by
        (unfold NR; simpl; ring). exact Hclamped_width.
    }
    pose proof (NR_reflect_lt (hi - lo) 1538 HwidthR). lia.
  }
  assert (Hscaled_lower_error :
    0 <= NR q768_scale * tp - NR lo < 1281).
  {
    rewrite Hlo_id.
    assert (Htp_gap :
      0 <= NR q768_scale * (tp - glo) <= 1026) by nra.
    nra.
  }

  repeat split.
  - apply (Rmult_le_reg_r (NR q768_scale)); [exact HS |].
    replace (NR lo / NR q768_scale * NR q768_scale)
      with (NR lo) by (field; lra).
    nra.
  - apply (Rmult_le_reg_r (NR q768_scale)); [exact HS |].
    replace (NR hi / NR q768_scale * NR q768_scale)
      with (NR hi) by (field; lra).
    nra.
  - exact HwidthN.
  - apply (Rmult_le_reg_r (NR q768_scale)); [exact HS |].
    replace ((tp - NR lo / NR q768_scale) * NR q768_scale)
      with (NR q768_scale * tp - NR lo) by (field; lra).
    nra.
  - apply (Rmult_lt_reg_r (NR q768_scale)); [exact HS |].
    replace ((tp - NR lo / NR q768_scale) * NR q768_scale)
      with (NR q768_scale * tp - NR lo) by (field; lra).
    replace (NR 1281 / NR q768_scale * NR q768_scale)
      with (NR 1281) by (field; lra).
    replace (NR 1281) with (1281 : R) by
      (unfold NR; simpl; ring).
    exact (proj2 Hscaled_lower_error).
Qed.

Theorem full_q768_abstract_target :
  forall f w total : N,
    admissible f w total ->
    let '(lo, hi) := certificate_model f w total in
    (NR lo / NR q768_scale <= true_probability f w total <= NR hi / NR q768_scale) /\
    (hi - lo <= 1537)%N /\
    (0 <= true_probability f w total - NR lo / NR q768_scale
      < NR 1281 / NR q768_scale).
Proof.
  intros f w total Hadmissible.
  rewrite certificate_model_shape.
  cbv beta iota zeta.
  eapply full_q768_abstract_assembly.
  - exact Hadmissible.
  - apply certificate_log_and_stake_bridge. exact Hadmissible.
  - apply stake_lower_endpoint_bound. exact Hadmissible.
  - reflexivity.
  - reflexivity.
  - reflexivity.
  - reflexivity.
Qed.

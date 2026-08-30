From Stdlib Require Import NArith ZArith Reals.

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

Definition true_probability (f w total : N) : R :=
  let fr := NR f / NR (2 ^ 64)%N in
  let alpha := NR w / NR total in
  1 - exp (- (alpha * (- ln (1 - fr)))).

Definition admissible (f w total : N) : Prop :=
  (1 <= f <= 2 ^ 63)%N /\ (1 <= w)%N /\ (w <= total)%N /\
  (total <= 2 ^ 64 - 1)%N.

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
  (* This is the exact end theorem. The finite recurrence arithmetic and
     composition pieces are checked in companion files; the two series-tail
     theorems in Q768AnalyticObligations.v remain to be supplied. *)
Abort.

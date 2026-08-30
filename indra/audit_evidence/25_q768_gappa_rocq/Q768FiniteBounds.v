From Stdlib Require Import NArith Lia.

Open Scope N_scope.

Definition q768_scale : N := 2 ^ 768.

Definition ceil_div (n d : N) : N := (n + d - 1) / d.

Definition mul_bound (a_hi b_hi wa wb : N) : N * N :=
  (ceil_div (a_hi * b_hi) q768_scale,
   ceil_div (b_hi * wa + a_hi * wb) q768_scale + 1).

Definition div_scalar_bound (a_hi wa d : N) : N * N :=
  (ceil_div a_hi d, ceil_div wa d + 1).

Record log_state := {
  power_hi : N;
  power_width : N;
  sum_hi : N;
  sum_width : N
}.

Definition advance_power (y2_hi y2_width : N) (st : log_state) : log_state :=
  let '(next_hi, next_width) :=
    mul_bound st.(power_hi) y2_hi st.(power_width) y2_width in
  {| power_hi := next_hi;
     power_width := next_width;
     sum_hi := st.(sum_hi);
     sum_width := st.(sum_width) |}.

Fixpoint log_terms
    (remaining n : nat) (y2_hi y2_width : N) (st : log_state) : log_state :=
  match remaining with
  | O => st
  | S remaining' =>
      let d := N.of_nat (2 * n + 1) in
      let '(term_hi, term_width) :=
        div_scalar_bound st.(power_hi) st.(power_width) d in
      let with_term :=
        {| power_hi := st.(power_hi);
           power_width := st.(power_width);
           sum_hi := st.(sum_hi) + term_hi;
           sum_width := st.(sum_width) + term_width |} in
      match remaining' with
      | O => with_term
      | S _ => log_terms remaining' (Nat.succ n) y2_hi y2_width
                   (advance_power y2_hi y2_width with_term)
      end
  end.

Definition y_hi : N := ceil_div q768_scale 3.
Definition y_width : N := 1.
Definition y2 : N * N := mul_bound y_hi y_hi y_width y_width.
Definition y2_hi : N := fst y2.
Definition y2_width : N := snd y2.

Definition initial_log_state : log_state :=
  {| power_hi := y_hi;
     power_width := y_width;
     sum_hi := 0;
     sum_width := 0 |}.

Definition final_log_state : log_state :=
  log_terms 256%nat 0%nat y2_hi y2_width initial_log_state.

Definition y513 : N * N :=
  mul_bound final_log_state.(power_hi) y2_hi
            final_log_state.(power_width) y2_width.

Definition log_tail : N :=
  ceil_div (2 * fst y513 * q768_scale)
           (513 * (q768_scale - y2_hi)).

Definition log_hi : N := 2 * final_log_state.(sum_hi) + log_tail.
Definition log_width : N := 2 * final_log_state.(sum_width) + log_tail.

Fixpoint phi_terms
    (remaining k : nat) (x_hi term_hi term_width accumulated_width : N) : N :=
  match remaining with
  | O => accumulated_width
  | S remaining' =>
      let current :=
        if Nat.eqb k 1%nat then (term_hi, term_width)
        else
          let '(mul_hi, mul_width) := mul_bound term_hi x_hi term_width 0 in
          div_scalar_bound mul_hi mul_width (N.of_nat k) in
      phi_terms remaining' (Nat.succ k) x_hi
                (fst current) (snd current) (accumulated_width + snd current)
  end.

Definition phi_rounding_width (terms : nat) : N :=
  phi_terms terms 1%nat log_hi log_hi 0 0.

Fixpoint factorial (n : nat) : N :=
  match n with
  | O => 1
  | S n' => N.of_nat n * factorial n'
  end.

Example log_sum_width_is_512 : final_log_state.(sum_width) = 512.
Proof. vm_compute. reflexivity. Qed.

Example analytic_log_tail_rounds_to_one : log_tail = 1.
Proof. vm_compute. reflexivity. Qed.

Example certified_log_width_is_1025 : log_width = 1025.
Proof. vm_compute. reflexivity. Qed.

Example certified_log_upper_is_below_seven_tenths :
  10 * log_hi < 7 * q768_scale.
Proof. vm_compute. reflexivity. Qed.

Example phi_128_rounding_width_is_254 : phi_rounding_width 128 = 254.
Proof. vm_compute. reflexivity. Qed.

Example phi_129_rounding_width_is_256 : phi_rounding_width 129 = 256.
Proof. vm_compute. reflexivity. Qed.

Example exp_tail_129_is_below_one_q768_unit :
  q768_scale * 7 ^ 129 < 10 ^ 129 * factorial 129%nat.
Proof. vm_compute. reflexivity. Qed.

Example exp_tail_130_is_below_one_q768_unit :
  q768_scale * 7 ^ 130 < 10 ^ 130 * factorial 130%nat.
Proof. vm_compute. reflexivity. Qed.

Definition z_uncertainty : N := log_width + 1.
Definition phi_width_strict_budget : N :=
  phi_rounding_width 129 + 1 + z_uncertainty + 1 + phi_rounding_width 128.
Definition phi_integer_width_bound : N := phi_width_strict_budget - 1.
Definition lower_error_strict_budget : N :=
  z_uncertainty + 1 + phi_rounding_width 128.

Example phi_width_strict_budget_is_1538 : phi_width_strict_budget = 1538.
Proof. vm_compute. reflexivity. Qed.

Example phi_integer_width_bound_is_1537 : phi_integer_width_bound = 1537.
Proof. vm_compute. reflexivity. Qed.

Example phi_integer_width_is_below_two_pow_24 :
  phi_integer_width_bound < 2 ^ 24.
Proof. vm_compute. reflexivity. Qed.

Example lower_error_strict_budget_is_1281 : lower_error_strict_budget = 1281.
Proof. vm_compute. reflexivity. Qed.

Example lower_error_is_below_two_pow_757 :
  lower_error_strict_budget * 2 ^ 757 < q768_scale.
Proof. vm_compute. reflexivity. Qed.

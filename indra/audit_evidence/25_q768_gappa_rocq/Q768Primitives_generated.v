Require Import Gappa.Gappa_library.
Section Generated_by_Gappa.
Variable _ah : R.
Variable _bh : R.
Definition r4 := (_ah * _bh)%R.
Definition _mhi := (rounding_fixed rndUP (-768)%Z) r4.
Variable _al : R.
Variable _bl : R.
Definition r8 := (_al * _bl)%R.
Definition _mlo := (rounding_fixed rndDN (-768)%Z) r8.
Definition r2 := (_mhi - _mlo)%R.
Definition r14 := (_ah - _al)%R.
Definition r13 := (_bh * r14)%R.
Definition r16 := (_bh - _bl)%R.
Definition r15 := (_al * r16)%R.
Definition r12 := (r13 + r15)%R.
Definition r17 := float2R (Float2 (1) (-767)).
Definition r11 := (r12 + r17)%R.
Definition _mul_delta := (r2 - r11)%R.
Definition r20 := (_mhi - r4)%R.
Definition r21 := (r8 - _mlo)%R.
Definition r19 := (r20 + r21)%R.
Definition r18 := (r19 - r17)%R.
Hypothesis a1 : _mul_delta = r18.
Lemma b1 : _mul_delta = r18.
 apply a1.
Qed.
Variable _d : R.
Definition r25 := (_ah / _d)%R.
Definition _dhi := (rounding_fixed rndUP (-768)%Z) r25.
Definition r28 := (_al / _d)%R.
Definition _dlo := (rounding_fixed rndDN (-768)%Z) r28.
Definition r23 := (_dhi - _dlo)%R.
Definition r30 := (r14 / _d)%R.
Definition r29 := (r30 + r17)%R.
Definition _div_delta := (r23 - r29)%R.
Definition r33 := (_dhi - r25)%R.
Definition r34 := (r28 - _dlo)%R.
Definition r32 := (r33 + r34)%R.
Definition r31 := (r32 - r17)%R.
Hypothesis a2 : _div_delta = r31.
Lemma b2 : _div_delta = r31.
 apply a2.
Qed.
Variable _x : R.
Definition f1 := Float2 (0) (0).
Definition f2 := Float2 (1) (0).
Definition i1 := makepairF f1 f2.
Definition p1 := BND _x i1. (* BND(x, [0, 1]) *)
Definition p2 := BND _al i1. (* BND(al, [0, 1]) *)
Definition s8 := p1 /\ p2.
Definition p3 := BND r14 i1. (* BND(ah - al, [0, 1]) *)
Definition s7 := s8 /\ p3.
Definition p4 := BND _ah i1. (* BND(ah, [0, 1]) *)
Definition s6 := s7 /\ p4.
Definition p5 := BND _bl i1. (* BND(bl, [0, 1]) *)
Definition s5 := s6 /\ p5.
Definition p6 := BND r16 i1. (* BND(bh - bl, [0, 1]) *)
Definition s4 := s5 /\ p6.
Definition p7 := BND _bh i1. (* BND(bh, [0, 1]) *)
Definition s3 := s4 /\ p7.
Definition f3 := Float2 (1) (64).
Definition i2 := makepairF f2 f3.
Definition p8 := BND _d i2. (* BND(d, [1, 1.84468e+19]) *)
Definition s2 := s3 /\ p8.
Definition _xd := (rounding_fixed rndDN (-768)%Z) _x.
Definition r36 := (_xd - _x)%R.
Definition f4 := Float2 (-1) (-768).
Definition i3 := makepairF f4 f1.
Definition p9 := BND r36 i3. (* BND(xd - x, [-6.44115e-232, 0]) *)
Definition s16 := not p9.
Definition _xu := (rounding_fixed rndUP (-768)%Z) _x.
Definition r38 := (_xu - _x)%R.
Definition f5 := Float2 (1) (-768).
Definition i4 := makepairF f1 f5.
Definition p10 := BND r38 i4. (* BND(xu - x, [0, 6.44115e-232]) *)
Definition s17 := not p10.
Definition s15 := s16 \/ s17.
Definition r40 := (_mlo - r8)%R.
Definition p11 := BND r40 i3. (* BND(mlo - al * bl, [-6.44115e-232, 0]) *)
Definition s18 := not p11.
Definition s14 := s15 \/ s18.
Definition p12 := BND r20 i4. (* BND(mhi - ah * bh, [0, 6.44115e-232]) *)
Definition s19 := not p12.
Definition s13 := s14 \/ s19.
Definition r41 := (_dlo - r28)%R.
Definition p13 := BND r41 i3. (* BND(dlo - al / d, [-6.44115e-232, 0]) *)
Definition s20 := not p13.
Definition s12 := s13 \/ s20.
Definition p14 := BND r33 i4. (* BND(dhi - ah / d, [0, 6.44115e-232]) *)
Definition s21 := not p14.
Definition s11 := s12 \/ s21.
Definition p15 := (_mul_delta <= f1)%R. (* BND(mul_delta, [-inf, 0]) *)
Definition s22 := not p15.
Definition s10 := s11 \/ s22.
Definition p16 := (_div_delta <= f1)%R. (* BND(div_delta, [-inf, 0]) *)
Definition s23 := not p16.
Definition s9 := s10 \/ s23.
Definition s1 := s2 /\ s9.
Definition s24 := s22 \/ s23.
Definition s26 := s21 \/ s22.
Definition s25 := s26 \/ s23.
Definition s29 := s20 \/ s21.
Definition s28 := s29 \/ s22.
Definition s27 := s28 \/ s23.
Definition s33 := s19 \/ s20.
Definition s32 := s33 \/ s21.
Definition s31 := s32 \/ s22.
Definition s30 := s31 \/ s23.
Definition s38 := s18 \/ s19.
Definition s37 := s38 \/ s20.
Definition s36 := s37 \/ s21.
Definition s35 := s36 \/ s22.
Definition s34 := s35 \/ s23.
Definition s44 := s17 \/ s18.
Definition s43 := s44 \/ s19.
Definition s42 := s43 \/ s20.
Definition s41 := s42 \/ s21.
Definition s40 := s41 \/ s22.
Definition s39 := s40 \/ s23.
Lemma l9 : s1 -> s9.
Proof.
 intros h0.
 assert (h1 := h0).
 exact (proj2 h1).
Qed.
Lemma t1 : p9.
Proof.
 refine (fixed_error_dn _ _ i3 _) ; finalize.
Qed.
Lemma l10 : s1 -> p9 (* BND(xd - x, [-6.44115e-232, 0]) *).
Proof.
 intros h0.
 apply t1.
Qed.
Lemma l8 : s1 -> s39.
Proof.
 intros h0.
 assert (h1 := l9 h0).
 assert (h2 := l10 h0).
 refine (simplify (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 0%nat i3)) (Tatom false (Abnd 1%nat i4))) (Tatom false (Abnd 2%nat i3))) (Tatom false (Abnd 3%nat i4))) (Tatom false (Abnd 4%nat i3))) (Tatom false (Abnd 5%nat i4))) (Tatom false (Aleq 6%nat f1))) (Tatom false (Aleq 7%nat f1))) (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 1%nat i4)) (Tatom false (Abnd 2%nat i3))) (Tatom false (Abnd 3%nat i4))) (Tatom false (Abnd 4%nat i3))) (Tatom false (Abnd 5%nat i4))) (Tatom false (Aleq 6%nat f1))) (Tatom false (Aleq 7%nat f1))) (Abnd 0%nat i3) (List.cons r36 (List.cons r38 (List.cons r40 (List.cons r20 (List.cons r41 (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil)))))))) h2 h1 _) ; finalize.
Qed.
Lemma t2 : p10.
Proof.
 refine (fixed_error_up _ _ i4 _) ; finalize.
Qed.
Lemma l11 : s1 -> p10 (* BND(xu - x, [0, 6.44115e-232]) *).
Proof.
 intros h0.
 apply t2.
Qed.
Lemma l7 : s1 -> s34.
Proof.
 intros h0.
 assert (h1 := l8 h0).
 assert (h2 := l11 h0).
 refine (simplify (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 0%nat i4)) (Tatom false (Abnd 1%nat i3))) (Tatom false (Abnd 2%nat i4))) (Tatom false (Abnd 3%nat i3))) (Tatom false (Abnd 4%nat i4))) (Tatom false (Aleq 5%nat f1))) (Tatom false (Aleq 6%nat f1))) (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 1%nat i3)) (Tatom false (Abnd 2%nat i4))) (Tatom false (Abnd 3%nat i3))) (Tatom false (Abnd 4%nat i4))) (Tatom false (Aleq 5%nat f1))) (Tatom false (Aleq 6%nat f1))) (Abnd 0%nat i4) (List.cons r38 (List.cons r40 (List.cons r20 (List.cons r41 (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil))))))) h2 h1 _) ; finalize.
Qed.
Lemma t3 : p11.
Proof.
 refine (fixed_error_dn _ _ i3 _) ; finalize.
Qed.
Lemma l12 : s1 -> p11 (* BND(mlo - al * bl, [-6.44115e-232, 0]) *).
Proof.
 intros h0.
 apply t3.
Qed.
Lemma l6 : s1 -> s30.
Proof.
 intros h0.
 assert (h1 := l7 h0).
 assert (h2 := l12 h0).
 refine (simplify (Ttree false (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 0%nat i3)) (Tatom false (Abnd 1%nat i4))) (Tatom false (Abnd 2%nat i3))) (Tatom false (Abnd 3%nat i4))) (Tatom false (Aleq 4%nat f1))) (Tatom false (Aleq 5%nat f1))) (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 1%nat i4)) (Tatom false (Abnd 2%nat i3))) (Tatom false (Abnd 3%nat i4))) (Tatom false (Aleq 4%nat f1))) (Tatom false (Aleq 5%nat f1))) (Abnd 0%nat i3) (List.cons r40 (List.cons r20 (List.cons r41 (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil)))))) h2 h1 _) ; finalize.
Qed.
Lemma t4 : p12.
Proof.
 refine (fixed_error_up _ _ i4 _) ; finalize.
Qed.
Lemma l13 : s1 -> p12 (* BND(mhi - ah * bh, [0, 6.44115e-232]) *).
Proof.
 intros h0.
 apply t4.
Qed.
Lemma l5 : s1 -> s27.
Proof.
 intros h0.
 assert (h1 := l6 h0).
 assert (h2 := l13 h0).
 refine (simplify (Ttree false (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 0%nat i4)) (Tatom false (Abnd 1%nat i3))) (Tatom false (Abnd 2%nat i4))) (Tatom false (Aleq 3%nat f1))) (Tatom false (Aleq 4%nat f1))) (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 1%nat i3)) (Tatom false (Abnd 2%nat i4))) (Tatom false (Aleq 3%nat f1))) (Tatom false (Aleq 4%nat f1))) (Abnd 0%nat i4) (List.cons r20 (List.cons r41 (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil))))) h2 h1 _) ; finalize.
Qed.
Lemma t5 : p13.
Proof.
 refine (fixed_error_dn _ _ i3 _) ; finalize.
Qed.
Lemma l14 : s1 -> p13 (* BND(dlo - al / d, [-6.44115e-232, 0]) *).
Proof.
 intros h0.
 apply t5.
Qed.
Lemma l4 : s1 -> s25.
Proof.
 intros h0.
 assert (h1 := l5 h0).
 assert (h2 := l14 h0).
 refine (simplify (Ttree false (Ttree false (Ttree false (Tatom false (Abnd 0%nat i3)) (Tatom false (Abnd 1%nat i4))) (Tatom false (Aleq 2%nat f1))) (Tatom false (Aleq 3%nat f1))) (Ttree false (Ttree false (Tatom false (Abnd 1%nat i4)) (Tatom false (Aleq 2%nat f1))) (Tatom false (Aleq 3%nat f1))) (Abnd 0%nat i3) (List.cons r41 (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil)))) h2 h1 _) ; finalize.
Qed.
Lemma t6 : p14.
Proof.
 refine (fixed_error_up _ _ i4 _) ; finalize.
Qed.
Lemma l15 : s1 -> p14 (* BND(dhi - ah / d, [0, 6.44115e-232]) *).
Proof.
 intros h0.
 apply t6.
Qed.
Lemma l3 : s1 -> s24.
Proof.
 intros h0.
 assert (h1 := l4 h0).
 assert (h2 := l15 h0).
 refine (simplify (Ttree false (Ttree false (Tatom false (Abnd 0%nat i4)) (Tatom false (Aleq 1%nat f1))) (Tatom false (Aleq 2%nat f1))) (Ttree false (Tatom false (Aleq 1%nat f1)) (Tatom false (Aleq 2%nat f1))) (Abnd 0%nat i4) (List.cons r33 (List.cons _mul_delta (List.cons _div_delta List.nil))) h2 h1 _) ; finalize.
Qed.
Definition f6 := Float2 (-1) (-767).
Definition i5 := makepairF f6 f1.
Definition p17 := BND _div_delta i5. (* BND(div_delta, [-1.28823e-231, 0]) *)
Definition p18 := _div_delta = r31. (* EQL(div_delta, dhi - ah / d + (al / d - dlo) - 1b-767) *)
Lemma t7 : p18.
Proof.
 refine (b2) ; finalize.
Qed.
Lemma l17 : s1 -> p18 (* EQL(div_delta, dhi - ah / d + (al / d - dlo) - 1b-767) *).
Proof.
 intros h0.
 apply t7.
Qed.
Definition p19 := BND r31 i5. (* BND(dhi - ah / d + (al / d - dlo) - 1b-767, [-1.28823e-231, 0]) *)
Definition f7 := Float2 (1) (-767).
Definition i6 := makepairF f1 f7.
Definition p20 := BND r32 i6. (* BND(dhi - ah / d + (al / d - dlo), [-0, 1.28823e-231]) *)
Definition p21 := BND r34 i4. (* BND(al / d - dlo, [-0, 6.44115e-232]) *)
Definition r43 := (r28 - r28)%R.
Definition r42 := (r43 - r41)%R.
Definition p22 := BND r42 i4. (* BND(al / d - al / d - (dlo - al / d), [-0, 6.44115e-232]) *)
Definition i7 := makepairF f1 f1.
Definition p23 := BND r43 i7. (* BND(al / d - al / d, [0, 0]) *)
Lemma t8 : p23.
Proof.
 refine (sub_refl _ i7 _) ; finalize.
Qed.
Lemma l22 : s1 -> p23 (* BND(al / d - al / d, [0, 0]) *).
Proof.
 intros h0.
 apply t8.
Qed.
Lemma t9 : p23 -> p13 -> p22.
Proof.
 intros h0 h1.
 refine (sub r43 r41 i7 i3 i4 h0 h1 _) ; finalize.
Qed.
Lemma l21 : s1 -> p22 (* BND(al / d - al / d - (dlo - al / d), [-0, 6.44115e-232]) *).
Proof.
 intros h0.
 assert (h1 := l22 h0).
 assert (h2 := l14 h0).
 apply t9. exact h1. exact h2.
Qed.
Lemma t10 : p22 -> p21.
Proof.
 intros h0.
 refine (sub_xars _ _ _ i4 h0) ; finalize.
Qed.
Lemma l20 : s1 -> p21 (* BND(al / d - dlo, [-0, 6.44115e-232]) *).
Proof.
 intros h0.
 assert (h1 := l21 h0).
 apply t10. exact h1.
Qed.
Lemma t11 : p14 -> p21 -> p20.
Proof.
 intros h0 h1.
 refine (add r33 r34 i4 i4 i6 h0 h1 _) ; finalize.
Qed.
Lemma l19 : s1 -> p20 (* BND(dhi - ah / d + (al / d - dlo), [-0, 1.28823e-231]) *).
Proof.
 intros h0.
 assert (h1 := l15 h0).
 assert (h2 := l20 h0).
 apply t11. exact h1. exact h2.
Qed.
Definition i8 := makepairF f7 f7.
Definition p24 := BND r17 i8. (* BND(1b-767, [1.28822e-231, 1.28823e-231]) *)
Lemma t12 : p24.
Proof.
 refine (constant2 _ i8 _) ; finalize.
Qed.
Lemma l23 : s1 -> p24 (* BND(1b-767, [1.28822e-231, 1.28823e-231]) *).
Proof.
 intros h0.
 apply t12.
Qed.
Lemma t13 : p20 -> p24 -> p19.
Proof.
 intros h0 h1.
 refine (sub r32 r17 i6 i8 i5 h0 h1 _) ; finalize.
Qed.
Lemma l18 : s1 -> p19 (* BND(dhi - ah / d + (al / d - dlo) - 1b-767, [-1.28823e-231, 0]) *).
Proof.
 intros h0.
 assert (h1 := l19 h0).
 assert (h2 := l23 h0).
 apply t13. exact h1. exact h2.
Qed.
Lemma t14 : p18 -> p19 -> p17.
Proof.
 intros h0 h1.
 refine (bnd_rewrite _div_delta r31 i5 h0 h1) ; finalize.
Qed.
Lemma l16 : s1 -> p17 (* BND(div_delta, [-1.28823e-231, 0]) *).
Proof.
 intros h0.
 assert (h1 := l17 h0).
 assert (h2 := l18 h0).
 apply t14. exact h1. exact h2.
Qed.
Lemma l2 : s1 -> s22.
Proof.
 intros h0.
 assert (h1 := l3 h0).
 assert (h2 := l16 h0).
 refine (simplify (Ttree false (Tatom false (Aleq 0%nat f1)) (Tatom false (Aleq 1%nat f1))) (Tatom false (Aleq 0%nat f1)) (Abnd 1%nat i5) (List.cons _mul_delta (List.cons _div_delta List.nil)) h2 h1 _) ; finalize.
Qed.
Definition p25 := BND _mul_delta i7. (* BND(mul_delta, [0, 0]) *)
Definition f8 := Float2 (-1) (-766).
Definition i9 := makepairF f8 f1.
Definition p26 := BND _mul_delta i9. (* BND(mul_delta, [-2.57646e-231, 0]) *)
Definition r45 := (_mul_delta - r18)%R.
Definition r44 := (r18 + r45)%R.
Definition p27 := BND r44 i9. (* BND(mhi - ah * bh + (al * bl - mlo) - 1b-767 + (mul_delta - (mhi - ah * bh + (al * bl - mlo) - 1b-767)), [-2.57646e-231, 0]) *)
Definition p28 := BND r18 i9. (* BND(mhi - ah * bh + (al * bl - mlo) - 1b-767, [-2.57646e-231, 0]) *)
Definition p29 := BND r19 i6. (* BND(mhi - ah * bh + (al * bl - mlo), [-0, 1.28823e-231]) *)
Definition p30 := BND r21 i4. (* BND(al * bl - mlo, [-0, 6.44115e-232]) *)
Definition r47 := (r8 - r8)%R.
Definition r46 := (r47 - r40)%R.
Definition p31 := BND r46 i4. (* BND(al * bl - al * bl - (mlo - al * bl), [-0, 6.44115e-232]) *)
Definition p32 := BND r47 i7. (* BND(al * bl - al * bl, [0, 0]) *)
Lemma t15 : p32.
Proof.
 refine (sub_refl _ i7 _) ; finalize.
Qed.
Lemma l31 : s1 -> p32 (* BND(al * bl - al * bl, [0, 0]) *).
Proof.
 intros h0.
 apply t15.
Qed.
Lemma t16 : p32 -> p11 -> p31.
Proof.
 intros h0 h1.
 refine (sub r47 r40 i7 i3 i4 h0 h1 _) ; finalize.
Qed.
Lemma l30 : s1 -> p31 (* BND(al * bl - al * bl - (mlo - al * bl), [-0, 6.44115e-232]) *).
Proof.
 intros h0.
 assert (h1 := l31 h0).
 assert (h2 := l12 h0).
 apply t16. exact h1. exact h2.
Qed.
Lemma t17 : p31 -> p30.
Proof.
 intros h0.
 refine (sub_xars _ _ _ i4 h0) ; finalize.
Qed.
Lemma l29 : s1 -> p30 (* BND(al * bl - mlo, [-0, 6.44115e-232]) *).
Proof.
 intros h0.
 assert (h1 := l30 h0).
 apply t17. exact h1.
Qed.
Lemma t18 : p12 -> p30 -> p29.
Proof.
 intros h0 h1.
 refine (add r20 r21 i4 i4 i6 h0 h1 _) ; finalize.
Qed.
Lemma l28 : s1 -> p29 (* BND(mhi - ah * bh + (al * bl - mlo), [-0, 1.28823e-231]) *).
Proof.
 intros h0.
 assert (h1 := l13 h0).
 assert (h2 := l29 h0).
 apply t18. exact h1. exact h2.
Qed.
Definition f9 := Float2 (1) (-766).
Definition i10 := makepairF f7 f9.
Definition p33 := BND r17 i10. (* BND(1b-767, [1.28822e-231, 2.57646e-231]) *)
Lemma t19 : p29 -> p33 -> p28.
Proof.
 intros h0 h1.
 refine (sub r19 r17 i6 i10 i9 h0 h1 _) ; finalize.
Qed.
Lemma l27 : s1 -> p28 (* BND(mhi - ah * bh + (al * bl - mlo) - 1b-767, [-2.57646e-231, 0]) *).
Proof.
 intros h0.
 assert (h1 := l28 h0).
 assert (h2 := l23 h0).
 apply t19. exact h1. refine (subset r17 i8 i10 h2 _) ; finalize.
Qed.
Definition p34 := BND r45 i7. (* BND(mul_delta - (mhi - ah * bh + (al * bl - mlo) - 1b-767), [0, 0]) *)
Definition p35 := _mul_delta = r18. (* EQL(mul_delta, mhi - ah * bh + (al * bl - mlo) - 1b-767) *)
Lemma t20 : p35.
Proof.
 refine (b1) ; finalize.
Qed.
Lemma l33 : s1 -> p35 (* EQL(mul_delta, mhi - ah * bh + (al * bl - mlo) - 1b-767) *).
Proof.
 intros h0.
 apply t20.
Qed.
Lemma t21 : p35 -> p34.
Proof.
 intros h0.
 refine (sub_of_eql _mul_delta r18 i7 h0 _) ; finalize.
Qed.
Lemma l32 : s1 -> p34 (* BND(mul_delta - (mhi - ah * bh + (al * bl - mlo) - 1b-767), [0, 0]) *).
Proof.
 intros h0.
 assert (h1 := l33 h0).
 apply t21. exact h1.
Qed.
Lemma t22 : p28 -> p34 -> p27.
Proof.
 intros h0 h1.
 refine (add r18 r45 i9 i7 i9 h0 h1 _) ; finalize.
Qed.
Lemma l26 : s1 -> p27 (* BND(mhi - ah * bh + (al * bl - mlo) - 1b-767 + (mul_delta - (mhi - ah * bh + (al * bl - mlo) - 1b-767)), [-2.57646e-231, 0]) *).
Proof.
 intros h0.
 assert (h1 := l27 h0).
 assert (h2 := l32 h0).
 apply t22. exact h1. exact h2.
Qed.
Lemma t23 : p27 -> p26.
Proof.
 intros h0.
 refine (val_xabs _ _mul_delta i9 h0) ; finalize.
Qed.
Lemma l25 : s1 -> p26 (* BND(mul_delta, [-2.57646e-231, 0]) *).
Proof.
 intros h0.
 assert (h1 := l26 h0).
 apply t23. exact h1.
Qed.
Definition p36 := (f1 <= _mul_delta)%R. (* BND(mul_delta, [0, inf]) *)
Lemma l34 : s1 -> p36 (* BND(mul_delta, [0, inf]) *).
Proof.
 intros h0.
 assert (h1 := l2 h0).
 exact (RIneq.Rlt_le _ _ (RIneq.Rnot_le_lt _ _ h1)).
Qed.
Lemma l24 : s1 -> p25 (* BND(mul_delta, [0, 0]) *).
Proof.
 intros h0.
 assert (h1 := l25 h0).
 assert (h2 := l34 h0).
 apply intersect_bh with (1 := h1) (2 := h2). finalize.
Qed.
Lemma l1 : s1 -> False.
Proof.
 intros h0.
 assert (h1 := l2 h0).
 assert (h2 := l24 h0).
 refine (simplify (Tatom false (Aleq 0%nat f1)) Tfalse (Abnd 0%nat i7) (List.cons _mul_delta List.nil) h2 h1 _) ; finalize.
Qed.
End Generated_by_Gappa.

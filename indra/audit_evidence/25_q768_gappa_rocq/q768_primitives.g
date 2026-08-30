# Q768 primitive outward-rounding obligations.  1b-768 = 2^-768.
@down = fixed<-768,dn>;
@up = fixed<-768,up>;

xd = down(x);
xu = up(x);
mlo = down(al * bl);
mhi = up(ah * bh);
dlo = down(al / d);
dhi = up(ah / d);

mul_delta = mhi - mlo - (bh * (ah - al) + al * (bh - bl) + 2b-768);
div_delta = dhi - dlo - ((ah - al) / d + 2b-768);

{
  x in [0,1] /\
  al in [0,1] /\ ah - al in [0,1] /\ ah in [0,1] /\
  bl in [0,1] /\ bh - bl in [0,1] /\ bh in [0,1] /\
  d in [1,18446744073709551615]
  ->
  xd - x in [-1b-768,0] /\ xu - x in [0,1b-768] /\
  mlo - al * bl in [-1b-768,0] /\ mhi - ah * bh in [0,1b-768] /\
  dlo - al / d in [-1b-768,0] /\ dhi - ah / d in [0,1b-768] /\
  mul_delta <= 0 /\ div_delta <= 0
}

mul_delta -> (mhi - ah * bh) + (al * bl - mlo) - 2b-768;
div_delta -> (dhi - ah / d) + (al / d - dlo) - 2b-768;

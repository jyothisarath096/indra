#include "dilithium2_seeded.h"

int indra_dilithium2_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho;
    const uint8_t *rhoprime;
    const uint8_t *key;
    polyvecl mat[K];
    polyvecl s1;
    polyvecl s1hat;
    polyveck s2;
    polyveck t1;
    polyveck t0;

    shake256(seedbuf, sizeof(seedbuf), seed, SEEDBYTES);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_uniform_eta(&s2, rhoprime, L);

    s1hat = s1;
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(&t1, &t1, &s2);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_DILITHIUM2_CLEAN_pack_pk(pk, rho, &t1);
    shake256(tr, TRBYTES, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_DILITHIUM2_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
    return 0;
}

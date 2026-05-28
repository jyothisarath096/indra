#ifndef INDRA_DILITHIUM2_SEEDED_H
#define INDRA_DILITHIUM2_SEEDED_H

#include <stddef.h>
#include <stdint.h>

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define N 256
#define K 4
#define L 4
#define POLYT1_PACKEDBYTES 320
#define POLYT0_PACKEDBYTES 416
#define POLYETA_PACKEDBYTES 96
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K * POLYT1_PACKEDBYTES)
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES \
    (2 * SEEDBYTES + TRBYTES + L * POLYETA_PACKEDBYTES + K * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES)

typedef struct {
    int32_t coeffs[N];
} poly;

typedef struct {
    poly vec[L];
} polyvecl;

typedef struct {
    poly vec[K];
} polyveck;

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(polyvecl *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);
void PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(polyveck *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(polyveck *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(polyveck *v);
void PQCLEAN_DILITHIUM2_CLEAN_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void PQCLEAN_DILITHIUM2_CLEAN_pack_pk(uint8_t pk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);
void PQCLEAN_DILITHIUM2_CLEAN_pack_sk(uint8_t sk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES],
                                      const uint8_t rho[SEEDBYTES],
                                      const uint8_t tr[TRBYTES],
                                      const uint8_t key[SEEDBYTES],
                                      const polyveck *t0,
                                      const polyvecl *s1,
                                      const polyveck *s2);

int indra_dilithium2_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

#endif

#ifndef INDRA_H
#define INDRA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INDRA_OK                  0
#define INDRA_ERR_NULL_POINTER   -1
#define INDRA_ERR_BUFFER_SMALL   -2
#define INDRA_ERR_INVALID_HEX    -3
#define INDRA_ERR_KEYGEN         -4
#define INDRA_ERR_TX_BUILD       -5
#define INDRA_ERR_SIGN           -6
#define INDRA_ERR_RANGE_PROOF    -7
#define INDRA_ERR_BALANCE        -8
#define INDRA_ERR_INVALID_PARAM  -9
#define INDRA_ERR_INTERNAL      -99

#define INDRA_CLASSICAL_PK_BYTES  32
#define INDRA_CLASSICAL_SK_BYTES  32
#define INDRA_PQ_PK_BYTES       2592
#define INDRA_PQ_SK_BYTES         32
#define INDRA_VALIDATOR_ID_BYTES  32
#define INDRA_BYTES32_LEN         32
#define INDRA_TX_ID_BYTES         32
#define INDRA_MNEMONIC_MAX_BYTES 300

typedef struct {
    uint8_t validator_id[INDRA_VALIDATOR_ID_BYTES];
    uint8_t classical_pk[INDRA_CLASSICAL_PK_BYTES];
    uint8_t pq_pk[INDRA_PQ_PK_BYTES];
    uint8_t classical_seed[INDRA_CLASSICAL_SK_BYTES];
    uint8_t pq_sk[INDRA_PQ_SK_BYTES];
    uint8_t bls_seed[INDRA_BYTES32_LEN];
    uint8_t vrf_seed[INDRA_BYTES32_LEN];
} IndraKeyPair;

typedef struct {
    uint8_t  utxo_id[INDRA_BYTES32_LEN];
    uint64_t value_spark;
    uint8_t  blinding[INDRA_BYTES32_LEN];
    uint64_t created_height;
    uint32_t tx_index;
    uint32_t out_index;
    uint8_t  spent;
} IndraUtxoEntry;

typedef struct {
    const uint8_t* recipient_classical_pk;
    uint64_t       amount_spark;
    uint64_t       fee_spark;
    const IndraUtxoEntry* utxos;
    size_t         utxo_count;
    const uint8_t* sender_classical_seed;
    const uint8_t* sender_pq_sk;
    const uint8_t* sender_pq_pk;
} IndraTxParams;

typedef struct {
    uint8_t  tx_id[INDRA_TX_ID_BYTES];
    uint8_t* tx_bytes;
    size_t   tx_bytes_len;
    uint64_t change_spark;
    uint8_t  change_blinding[INDRA_BYTES32_LEN];
    size_t*  spent_indices;
    size_t   spent_count;
} IndraTxResult;

int32_t indra_keygen(
    const uint8_t* seed,
    IndraKeyPair* out
);

int32_t indra_generate_mnemonic(
    char* out_phrase,
    size_t out_len
);

int32_t indra_keygen_from_mnemonic(
    const char* phrase,
    IndraKeyPair* out
);

int32_t indra_validate_mnemonic(const char* phrase);

int32_t indra_validator_id(
    const uint8_t* classical_pk,
    uint8_t* out_id
);

int32_t indra_build_tx(
    const IndraTxParams* params,
    IndraTxResult* out
);

int32_t indra_tx_to_hex(
    const uint8_t* tx_bytes,
    size_t tx_bytes_len,
    char* out_hex,
    size_t out_hex_len
);

int32_t indra_genesis_utxo_blinding(
    const uint8_t* classical_pk,
    uint8_t* out_blinding
);

int32_t indra_verify_range_proof(
    const uint8_t* commitment_bytes,
    const uint8_t* proof_bytes,
    size_t proof_len
);

void indra_free_bytes(uint8_t* ptr, size_t len);
void indra_free_usize(size_t* ptr, size_t len);
const char* indra_error_string(int32_t error_code);

#ifdef __cplusplus
}
#endif

#endif

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
#define INDRA_ERR_INVALID_JSON  -10
#define INDRA_ERR_UNKNOWN_ACTION -11
#define INDRA_ERR_INVALID_VOTE  -12
#define INDRA_ERR_INVALID_HANDLE -13
#define INDRA_ERR_INTERNAL      -99

#define INDRA_OP_HEX_MAX_BYTES 32768
#define INDRA_CLASSICAL_PK_BYTES  32
#define INDRA_CLASSICAL_SK_BYTES  32
#define INDRA_PQ_PK_BYTES       2592
#define INDRA_PQ_SK_BYTES         32
#define INDRA_VALIDATOR_ID_BYTES  32
#define INDRA_VRF_PK_BYTES        32
#define INDRA_BYTES32_LEN         32
#define INDRA_TX_ID_BYTES         32
#define INDRA_MNEMONIC_MAX_BYTES 300
#define INDRA_PAYMENT_KEYPAIR_V1_BYTES 97
#define INDRA_PAYMENT_PUBKEY_V1_BYTES 1601
#define INDRA_PAYMENT_NOTE_V1_BYTES 1665

typedef uint64_t IndraKeyHandle;
#define INDRA_KEY_HANDLE_INVALID ((IndraKeyHandle)0)

typedef struct {
    uint8_t validator_id[INDRA_VALIDATOR_ID_BYTES];
    uint8_t classical_pk[INDRA_CLASSICAL_PK_BYTES];
    uint8_t pq_pk[INDRA_PQ_PK_BYTES];
    uint8_t vrf_pk[INDRA_VRF_PK_BYTES];
} IndraPublicKeyInfo;

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
    const uint8_t* recipient_address;
    size_t         recipient_address_len;
    uint64_t       amount_spark;
    uint64_t       fee_spark;
    const IndraUtxoEntry* utxos;
    size_t         utxo_count;
    IndraKeyHandle sender_handle;
    const char*    chain_id;
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

int32_t indra_keygen_handle(
    const uint8_t* seed,
    IndraKeyHandle* out_handle,
    IndraPublicKeyInfo* out_public
);

int32_t indra_generate_mnemonic(
    char* out_phrase,
    size_t out_len
);

int32_t indra_keygen_from_mnemonic_handle(
    const char* phrase,
    IndraKeyHandle* out_handle,
    IndraPublicKeyInfo* out_public
);

int32_t indra_key_handle_public(
    IndraKeyHandle handle,
    IndraPublicKeyInfo* out_public
);

int32_t indra_payment_keygen(
    uint8_t* out_keypair,
    uint8_t* out_pubkey
);

int32_t indra_key_handle_payment_pubkey(
    IndraKeyHandle handle,
    uint8_t* out_pubkey
);

int32_t indra_key_handle_payment_keypair(
    IndraKeyHandle handle,
    uint8_t* out_keypair
);

int32_t indra_destroy_key_handle(IndraKeyHandle handle);
int32_t indra_destroy_all_key_handles(void);

void indra_zeroize_tx_result(IndraTxResult* result);

int32_t indra_validate_mnemonic(const char* phrase);

int32_t indra_validator_id(
    const uint8_t* classical_pk,
    uint8_t* out_id
);

int32_t indra_build_tx_with_handle(
    const IndraTxParams* params,
    IndraTxResult* out
);

int32_t indra_derive_payment_note(
    const uint8_t* payment_pubkey,
    const uint8_t* owner_id,
    const char* chain_id,
    uint32_t output_index,
    uint64_t value_spark,
    uint64_t lock_height,
    uint8_t* out_note,
    uint8_t* out_blinding
);

int32_t indra_recover_payment_blinding(
    const uint8_t* payment_keypair,
    const uint8_t* note,
    const char* chain_id,
    uint32_t output_index,
    uint64_t value_spark,
    uint64_t lock_height,
    uint8_t* out_blinding
);

int32_t indra_recover_payment_blinding_with_handle(
    IndraKeyHandle handle,
    const uint8_t* note,
    const char* chain_id,
    uint32_t output_index,
    uint64_t value_spark,
    uint64_t lock_height,
    uint8_t* out_blinding
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

int32_t indra_build_register_validator_with_handle(
    uint32_t commission_bps,
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_self_stake_with_handle(
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_delegate_with_handle(
    const uint8_t* validator_id,
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_claim_rewards_with_handle(
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_set_commission_with_handle(
    uint32_t new_commission_bps,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_set_auto_delegate_with_handle(
    const uint8_t* target_validator_id,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_propose_with_handle(
    const char* title,
    const char* description,
    const char* action_json,
    const uint8_t* deposit_utxo_id,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_commit_with_handle(
    const uint8_t* proposal_id,
    uint8_t vote,
    const uint8_t* reveal_nonce,
    uint8_t* out_commitment,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_reveal_with_handle(
    const uint8_t* proposal_id,
    uint8_t vote,
    const uint8_t* reveal_nonce,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_redelegate_with_handle(
    const uint8_t* proposal_id,
    const uint8_t* from_validator_id,
    const uint8_t* to_validator_id,
    uint64_t amount_spark,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_execute_with_handle(
    const uint8_t* proposal_id,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_cancel_with_handle(
    const uint8_t* proposal_id,
    IndraKeyHandle handle,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_compute_vote_commitment(
    uint8_t vote,
    const uint8_t* reveal_nonce,
    uint8_t* out_commitment
);

/*
 * Transitional migration surface only. These raw-key declarations correspond
 * to Rust symbols compiled with Cargo feature `legacy_raw_keys`; production
 * wallet builds must not enable that feature and should not define this macro.
 */
#ifdef INDRA_ENABLE_LEGACY_RAW_KEYS
typedef struct {
    uint8_t validator_id[INDRA_VALIDATOR_ID_BYTES];
    uint8_t classical_pk[INDRA_CLASSICAL_PK_BYTES];
    uint8_t pq_pk[INDRA_PQ_PK_BYTES];
    uint8_t classical_seed[INDRA_CLASSICAL_SK_BYTES];
    uint8_t pq_sk[INDRA_PQ_SK_BYTES];
    uint8_t vrf_seed[INDRA_BYTES32_LEN];
} IndraKeyPair;

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

int32_t indra_keygen(const uint8_t* seed, IndraKeyPair* out);
int32_t indra_keygen_from_mnemonic(const char* phrase, IndraKeyPair* out);
void indra_zeroize_keypair(IndraKeyPair* keypair);

int32_t indra_build_tx(const IndraTxParams* params, IndraTxResult* out);

int32_t indra_build_register_validator(
    uint32_t commission_bps,
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    const uint8_t* vrf_pk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_self_stake(
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_delegate(
    const uint8_t* validator_id,
    const uint8_t* deposit_utxo_id,
    uint64_t bond_value_spark,
    const uint8_t* deposit_blinding_factor,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_claim_rewards(
    const uint8_t* validator_id,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_set_commission(
    const uint8_t* validator_id,
    uint32_t new_commission_bps,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_set_auto_delegate(
    const uint8_t* validator_id,
    const uint8_t* target_validator_id,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_propose(
    const char* title,
    const char* description,
    const char* action_json,
    const uint8_t* deposit_utxo_id,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_commit(
    const uint8_t* proposal_id,
    uint8_t vote,
    const uint8_t* reveal_nonce,
    uint8_t* out_commitment,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_reveal(
    const uint8_t* proposal_id,
    uint8_t vote,
    const uint8_t* reveal_nonce,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_redelegate(
    const uint8_t* proposal_id,
    const uint8_t* from_validator_id,
    const uint8_t* to_validator_id,
    uint64_t amount_spark,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_execute(
    const uint8_t* proposal_id,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);

int32_t indra_build_governance_cancel(
    const uint8_t* proposal_id,
    const uint8_t* classical_seed,
    const uint8_t* pq_pk,
    const uint8_t* pq_sk,
    uint64_t nonce,
    const char* chain_id,
    char* out_hex,
    size_t out_len
);
#endif

void indra_free_bytes(uint8_t* ptr, size_t len);
void indra_free_usize(size_t* ptr, size_t len);
const char* indra_error_string(int32_t error_code);

#ifdef __cplusplus
}
#endif

#endif

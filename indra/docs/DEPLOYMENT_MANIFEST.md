# INDRA Testnet-3 Deployment Manifest

> Historical deployment record. The checked-in `releases/genesis.toml` is an
> obsolete testnet-1 artifact and is not the genesis of the validators listed
> here. It must not be used with the current protocol. T14-03 regeneration of
> the next release manifest is intentionally deferred until a real future
> Bitcoin entropy block has reached the declared confirmation depth.

## Deployment

- **Chain ID:** `indra-testnet-3`
- **Deployment date:** 2026-08-11
- **Validator count:** 4
- **Stake per validator:** 100,000,000,000 Spark
- **Total validator stake:** 400,000,000,000 Spark

This deployment is a full identity change from the prior
`indra-testnet-2` network. All four validator identities were generated fresh;
they are not continuations of the testnet-2 validators. The redeployment
followed the comprehensive security and legacy-code sweep of the codebase.

## Cold custody

All four validators use simplified single-custodian cold custody for this
testnet deployment. The previously planned starboy 2-of-3 Shamir ceremony is
not in use on this network and is deferred to a future mainnet deployment.

This manifest contains public deployment facts only. Keystore passwords,
mnemonics, private keys, and other secret material must never be recorded here.

The next deployment record must additionally publish the canonical genesis
fingerprint, genesis block hash, state and consensus-snapshot roots, monetary
ledger identity, active-slot coefficient, complete Bitcoin entropy descriptor
and 80-byte header, and each validator's verified VRF proof of possession.

Genesis assembly is fail-closed on Bitcoin entropy verification. Operators run
`indra-genesis build ... --bitcoin-cli /path/to/bitcoin-cli`; the tool queries a
local Bitcoin Core node for the announced height on its active most-work chain,
locally double-SHA-256 checks the returned 80-byte header against that block
hash, verifies the configured Bitcoin network genesis hash, and requires the
declared confirmation floor. `indra-genesis verify-bitcoin-entropy` repeats the
same checks for an assembled manifest. There is no deadline or offline fallback.

## Validators

| Name | Validator ID | Server IP | Stake |
|---|---|---|---:|
| buddhi | `6171aa3a8f9a5ae1e17bb21b2d7624cc85df7fe6aea2cbe70a403393ffa3115a` | `116.203.185.28` | 100,000,000,000 Spark |
| bonkai | `1fad8ce319786403be14fb724ea58132ed89ff4ed92094b7447f2a73bd10dbc3` | `5.161.221.10` | 100,000,000,000 Spark |
| siddhi | `094850888758342ab10d6b4a460b57f50b26966ae5f932883f20f0f65053c0a3` | `178.104.151.220` | 100,000,000,000 Spark |
| starboy | `623f1d1219ac53bd79e9074cba27cf6950dc82385bed75f925d145a13d288cae` | `5.161.98.155` | 100,000,000,000 Spark |

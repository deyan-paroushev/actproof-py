# Anchor backends: design intent (v0.4.0)

actproof currently ships Algorand as its only public-witness backend.
This document records the architectural direction for v0.4.0: a
pluggable anchor backend layer that extends the chain-agnostic
substrate (canonicalization, RFC 3161 timestamps, receipt format,
verifier) to other public ledgers without changing the substrate
semantics.

This note is intentionally a design *intent*, not an implementation.
No empty interfaces or speculative types ship in v0.3.0. The point is
to make the v0.4.0 direction legible to readers of the v0.3.0
codebase and to grant reviewers.

## Why pluggable backends

The library's value is split between two layers:

1. **Substrate** (chain-agnostic): RFC 8785 canonical JSON, RFC 3161
   trusted timestamps, the receipt format, the verifier.
2. **Anchoring** (chain-specific): transaction construction, signer
   policy, on-chain submission, anchor record resolution.

Roughly 70 percent of the library's lines of code and conceptual
weight sit in Layer 1. Layer 2 is one binding among many that could
exist. Pluggable backends make this explicit and let downstream
adopters choose the chain that fits their jurisdictional, cost, and
finality requirements.

## Architectural shape

The v0.4.0 abstraction will be `AnchorBackend`, not a generalized
signer interface. Signing is chain-specific (the bytes-to-sign, the
key algorithm, the address derivation, and the validation policy all
differ). Anchoring is the verb the substrate cares about: take a
commitment, submit it to a public witness, get back a receipt entry
the verifier can later resolve.

Approximate shape:

```python
class AnchorBackend(Protocol):
    backend_id: str  # "algorand_arc2", "hedera_hcs", "stellar_memo_hash", ...

    def build_payload(self, commitment: bytes, *, metadata: dict) -> bytes:
        ...

    def submit(self, payload: bytes) -> AnchorReceipt:
        ...

    def verify(
        self,
        anchor: AnchorReceipt,
        commitment: bytes,
    ) -> AnchorVerificationResult:
        ...
```

Concrete backends remain chain-specific:

- `AlgorandAnchorBackend` (today's `actproof.anchor`)
- `HederaHCSAnchorBackend`
- `StellarMemoHashAnchorBackend`
- `BitcoinOpReturnAnchorBackend`
- `EthereumCalldataAnchorBackend`

Signers stay chain-specific too: `AlgorandSigner`,
`HederaTopicSubmitter`, `StellarTransactionSigner`. The substrate does
not pretend these share a single safe signing policy. They do not.

## Receipt format evolution

The current receipt embeds a single Algorand anchor. v0.4.0 receipts
will use an `anchors[]` list so a single attestation can carry
witnesses on multiple chains:

```json
{
  "anchors": [
    {
      "backend": "algorand",
      "network": "mainnet",
      "anchor_type": "payment_note_arc2",
      "commitment_hash": "sha256:...",
      "transaction_id": "...",
      "round": 123,
      "block_time": "2026-05-17T...",
      "explorer_url": "..."
    },
    {
      "backend": "hedera_hcs",
      "network": "mainnet",
      "topic_id": "0.0.x",
      "sequence_number": 123,
      "consensus_timestamp": "...",
      "running_hash": "..."
    }
  ]
}
```

v0.3.0 receipts remain valid in v0.4.0: a single Algorand anchor maps
to a one-element `anchors[]` list. The verifier accepts both shapes.

## Backend priority

The intended implementation order, with rationale:

1. **Algorand** (done). Already operational.
2. **Hedera Consensus Service**. Purpose-built for tamper-proof
   message submission with consensus timestamps. Already used in
   production for DIDs and verifiable credentials. Python SDK
   (`hiero_sdk_python`) released January 2026.
3. **Stellar memo-hash**. 32-byte hash memo fits a SHA-256
   commitment exactly. Mature Python SDK (`stellar-sdk` 14+).
4. **Bitcoin OP_RETURN**. 80-byte payload. Operationally heavier but
   provides long-term credibility for adversarial environments.
5. **Ethereum calldata**. Last, because gas economics and smart-
   contract design expand the review surface most.

## Out of scope for v0.4.0

- A unified signer interface across chains. Signing is chain-
  specific.
- Cross-chain consensus or bridging. The substrate produces evidence
  that can be witnessed on multiple chains independently; it does
  not coordinate witnesses.
- Anchor selection logic ("pick the cheapest available backend").
  Backend choice is the operator's, not the library's.

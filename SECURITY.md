# Security advisory: actproof v0.2.0

## Summary

actproof v0.2.0 (released to PyPI on 17 May 2026) contains a
transaction-validation gap in `actproof.signers.AlgorandSigner.validate_transaction`.
The signer accepts Algorand transactions that carry `rekey_to`,
`close_remainder_to`, arbitrary `fee`, `group`, or `lease` fields, as
long as the sender, receiver, amount, and note prefix pass validation.

An attacker who can construct an `algosdk.transaction.Transaction` and
pass it to `sign_transaction` can therefore have the signer authorise a
transaction that looks like a benign 0-ALGO self-payment but actually
transfers signing authority of the account to an address the attacker
controls (`rekey_to`), drains the account's remaining balance
(`close_remainder_to`), or burns ALGO via an inflated `fee`.

The Algorand `rekey_to` field is the same attack class that drained
roughly 3.3 million USD across approximately 25 accounts in the
February 2023 MyAlgo wallet incident.

## Severity

High. Exploitation requires the attacker to have the ability to
construct and submit a transaction to the signer (i.e. application-
layer compromise above the signer). The KMS key itself remains
protected by the HSM. However, the signer is the trust boundary the
package advertises, so the gap weakens the security guarantee the
package was meant to provide.

## Affected versions

- `actproof` 0.2.0 (the only public release as of this advisory)

## Fixed in

- `actproof` 0.3.0

## Mitigation if upgrading is not immediate

Audit all call sites that pass a `Transaction` object to
`AlgorandSigner.sign_transaction`. Verify that every `Transaction`
passed is constructed by code you control and that no path constructs
a `Transaction` with `rekey_to`, `close_remainder_to`, `group`, or
`lease` set.

## Fix in v0.3.0

`validate_transaction` now rejects:

1. Any transaction that is not a `PaymentTxn` (rejects
   `AssetTransferTxn`, `ApplicationCallTxn`, `KeyregTxn`, and other
   transaction classes).
2. Any transaction with `rekey_to` set.
3. Any transaction with `close_remainder_to` set.
4. Any transaction with `group` set.
5. Any transaction with `lease` set.
6. Any transaction with `fee` outside
   `[ALGORAND_MIN_FEE_MICROALGOS, max_fee_microalgos]` (default range:
   exactly 1000 microALGO).

The two booleans `require_self_payment` and `require_zero_amount`
that earlier drafts of v0.3.0 added as configurable kwargs were
removed. The strict actproof anchoring shape (0-ALGO self-payment,
tagged note, no rekey/close/group/lease) is now non-configurable.

The only remaining configurable policy parameters are
`allowed_note_prefixes` (the legitimate point of variation between
actproof, Quoruna, and other downstream anchoring schemes) and
`max_fee_microalgos` (so callers can anchor during network congestion
with an explicit, auditable decision).

## GCP KMS hardening

In addition to the transaction-policy fix, v0.3.0 implements Google's
recommended end-to-end integrity verification pattern for KMS
responses, fail-closed on every check. See
`actproof/signers/google_kms.py` and the v0.3.0 changelog entry.

## Acknowledgements

Independent review by ChatGPT (May 2026) flagged the
`rekey_to`/`close_remainder_to` gap and the KMS integrity-check
weakening. Both findings are addressed in v0.3.0.

## Contact

For security questions, open a GitHub issue at
https://github.com/deyan-paroushev/actproof-py or email the address
in `pyproject.toml`.

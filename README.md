# kemproof

Attest that an **ML-KEM-768** key exchange really happened — and record it in a
way anyone can check later.

Post-quantum key exchange in production is easy to claim and hard to prove. This
is the smallest thing that turns the claim into a record: an exchange took place,
with this algorithm, at this time, valid until then.

---

## What this proves

- A party could complete an ML-KEM-768 encapsulation against a fresh public key
- The verifier could decapsulate it and reach the same shared secret
- It happened at a known time, and the record expires

## What this does **not** prove

Read this part twice. It is the reason the project exists.

- **It does not encrypt anything.** The shared secret is used to derive a
  fingerprint and is then discarded. No traffic is protected by it.
- **It is not a tunnel, and not a replacement for TLS.** Your transport
  security is whatever it was before.
- **It is not hybrid.** One KEM, not a KEM combined with a classical exchange.
- **It says nothing about today's traffic.** It says an exchange was possible.

If you need protected traffic, you need a protocol, not an attestation. If you
need to show an auditor that post-quantum key exchange runs in your estate and
when it last ran, that is this.

## How it works

```
verifier                             prover
   |  handshake                         |
   |----------- public key ------------>|
   |                                    |  encapsulate (liboqs)
   |<--------- ciphertext --------------|
   |  decapsulate                       |
   |  fingerprint = HMAC(secret, sid)   |
   |  store: alg, time, expiry          |
   |  discard the secret                |
```

Three steps, and the secret survives none of them.

## Requirements

- `liboqs` — the crypto is [Open Quantum Safe](https://openquantumsafe.org),
  not ours. This project is the record around it.
- PHP 8.0+ with the `ffi` extension, for the verifier
- Python 3.8+ for the reference client

## Use

```php
$kem = new KemProof\KemAttestation('/path/to/liboqs.so', $yourStore);

$hs = $kem->handshake();                  // hand out $hs['public_key']
$record = $kem->attest($subject, $hs['session_id'], $hs['secret_key'], $ct);
$status = $kem->status($subject);         // null if never attested
```

`status()` returns `null` when a subject was never attested, and a record with
`valid => false` when it expired. **Those are different answers** and the caller
should not collapse them: never measured is not the same as measured and stale.

Storage is yours. Implement `StoreInterface` over a table, a file, a cache.

```bash
python3 client/attest.py https://example.org/kem/v1 my-subject /path/to/liboqs.so
```

## Where this comes from

LANGA runs 16 digital services across 5 networks on its own infrastructure.
ML-KEM-768 key exchange runs across them, and this is the part that records it.

Writing the honest version of the claim was the harder half: our own public
pages said *encryption* where the code did *key exchange*, and the two are not
the same promise. That is written up here:
[Post-quantum key exchange in production, and what it is not](https://about.langa.tv/how-we-work/qcrypto/).

The ecosystem it runs in:

- [LANGA](https://langa.tv) — the ecosystem
- [LINK](https://link.langa.tv) — monitoring and security for any website
- [easy LANGA](https://easy.langa.tv) — client management, reports, support
- [LANGA Tools](https://tools.langa.tv) — WordPress toolkit for developers

See [How we work](https://about.langa.tv/how-we-work/).

## Licence

MIT — see LICENSE. Copyright LANGA Corporation S.r.l.

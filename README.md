# kemproof

[![self-test](https://github.com/langacorp/kemproof/actions/workflows/selftest.yml/badge.svg)](https://github.com/langacorp/kemproof/actions/workflows/selftest.yml)
[![packagist](https://img.shields.io/packagist/v/langacorp/kemproof)](https://packagist.org/packages/langacorp/kemproof)

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

## Install

```bash
composer require langacorp/kemproof
```

The package is the PHP verifier under `src/`. `liboqs` is a system library and
is not installed by Composer: it has to be present on the machine already.

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

## The other tools

Each came out of a defect measured on our own estate. Each one is standalone
and depends on none of the others.

- **[realroute](https://github.com/langacorp/realroute)** — checks that a route
  really exists, by content and not by status code.
- **[leakform](https://github.com/langacorp/leakform)** — finds secrets in a git
  repository by shape, across every ref.
- **[samecheck](https://github.com/langacorp/samecheck)** — measures whether the
  copies that should be identical still are, and never says which one is right.
- **[provenreal](https://github.com/langacorp/provenreal)** — compares what a
  system claims with what can be measured, from independent sources.
- **[countdrift](https://github.com/langacorp/countdrift)** — finds numbers
  written by hand that no longer match their source.

The set is kept on the [organisation profile](https://github.com/langacorp).
It is not written here as a count, because a number typed by hand is the thing
countdrift exists to find.

## Where this comes from

LANGA runs an ecosystem of digital services on its own infrastructure, and this
is the part that records ML-KEM-768 exchanges within it.

Two layers are involved and they are not the same. Connections to the sites
served on our Galaxy infrastructure negotiate ML-KEM-768 at the **TLS layer**:
65 hosts out of 65, measured on 3 September 2026 by reading the negotiated group
in the ServerHello, querying the server address rather than the public name. Not
yet enabled on LINK, our client-hosting infrastructure, at that layer. This tool
records something else — an **application-level** exchange, run on top of
whatever transport is already in place. Anyone checking with `openssl` is
measuring the first and never the second, which is why each claim here says
which layer it means.

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

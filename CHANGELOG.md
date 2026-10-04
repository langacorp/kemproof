# Changelog

All notable changes to this project are recorded here.
Each entry is a release. The heading carries the tag and the date the release
was published. Work that is tagged but never released says so.

## v2.0.0 — 2026-10-04

Breaking: `attest()` takes a key confirmation, and a 1.x client is refused.

- **Key confirmation.** Up to 1.2.0 a record did not show that the prover
  reached the same shared secret: ML-KEM decapsulation uses implicit
  rejection, and 1088 random bytes were attested with `valid => true`
  (measured with liboqs 0.16.0). The prover now sends
  HMAC-SHA256(shared secret, transcript), the transcript binding the session,
  the subject, the public key and the ciphertext with length-prefixed fields.
  The verifier compares in constant time and throws, storing nothing, on a
  mismatch. Tests against real liboqs: a flipped bit, a random ciphertext, a
  confirmation moved to another subject, session or keypair, one made with a
  wrong secret and one of zeros are all refused; with the check disabled on
  purpose the same tests fail.
- Records carry `protocol => 'kemproof/2'` and `confirmed => true`.
- The client sends the confirmation. Its `encapsulate()` returns
  `(ciphertext, shared_secret)` and clears the liboqs buffer.
- `examples/verifier.php`: a reference endpoint for the client. The secret
  key stays on the server, a session is single-use (claimed by rename, so a
  replay or a retry after a refusal gets 404), sessions expire after five
  minutes, the subject must match the handshake. Errors map to 400, 403 or
  500, and no stack trace reaches the prover.
- Secret buffers are cleared: the FFI buffers for the secret key and the
  shared secret, and the PHP copy of the shared secret (`sodium_memzero`
  when available). Best effort: PHP may hold other copies.
- Outside the CLI, PHP's default `ffi.enable=preload` made `FFI::cdef()` throw
  an `FFI\Exception` that escaped as an uncaught error. It is now a
  `RuntimeException` that says which setting to change.
- `tests/vector.php` and the client tests pin the same confirmation bytes, so
  the PHP and Python transcripts cannot drift apart unnoticed. An end-to-end
  test runs the Python client against the reference verifier under `php -S`,
  with real liboqs on both sides.
- composer.json said "signed record". Nothing is signed: it is a record with
  an HMAC fingerprint. The description now says what it is.

## v1.2.0 — 2026-10-04

- CHANGELOG: one entry per release, so a reader can tell which version brought
  what. The three releases of 2026-09-04 were a single dated entry; they are now
  three, and the tag with no release says so.
- `StoreInterface` is in its own file, `src/StoreInterface.php`. composer.json
  maps `KemProof\` to `src/` by PSR-4, and the interface lived inside
  `KemAttestation.php`: with the package installed by Composer, implementing a
  store before touching `KemAttestation` failed with "Interface not found".
  Requiring `KemAttestation.php` by hand still works.
- `attest()` refuses a secret key that is not 2400 bytes, as it already did
  for a ciphertext that is not 1088. Before, a longer key was cut to 2400
  bytes and attested without a word, and a shorter one failed inside FFI. A
  caller passing a wrong-length key now gets a `RuntimeException` that names
  the length. No change to how keys, ciphertexts or secrets are handled.
- Client: the subject is URL-encoded in the handshake request. Before, a
  subject with `&` or `#` reached the handshake cut short while the
  attestation was posted for the full subject, and a space or a non-ASCII
  character raised an exception.
- README: a record does not show that the prover reached the same secret.
  ML-KEM-768 uses implicit rejection, and a random 1088-byte ciphertext is
  attested with `valid => true`; measured with liboqs. The line that said the
  verifier reaches "the same shared secret" now says what is checked.
- Tests: `tests/autoload.php`, `tests/lengths.php`, `tests/exchange.php` (a
  real ML-KEM-768 exchange, with `KEMPROOF_LIBOQS`) and `tests/test_client.py`
  (stdlib unittest, local HTTP server, no network). Each fails on the code it
  was written against before the fix.
- Self-test: builds liboqs 0.16.0 from its tag and runs a real exchange on
  PHP 8.0, 8.2 and 8.4; validates composer.json; runs the client tests on
  Python 3.8 and 3.13. actions/checkout@v5, actions/setup-python@v6.

## v1.1.3 — 2026-09-04

- README: PHP 8.0 is a floor, not a recommendation. It no longer receives
  security fixes upstream. The code runs on it; that is a different sentence
  from run it, and a reader takes the second one if you do not write the first.
- CITATION.cff said version 1.0.0 two releases after 1.0.0, and Zenodo reads
  that file: the archived record takes its abstract from it word for word.
  Version and date now match the release, and the concept DOI is in it.

## v1.1.2 — 2026-09-04

- composer.json required PHP 8.1 while the README promised 8.0, nine lines
  from the install command. Measured, not chosen: the code parses on 8.0 and a
  real ML-KEM-768 exchange completes on it. The floor is 8.0, and the self-test
  now runs on 8.0, 8.2 and 8.4 so the declared floor is an exercised one.
- README: DOI badge. The concept DOI, which follows every future release.

## v1.1.1 — 2026-09-04

- README: the package is on Packagist, and says so — badge and the one-line
  install. Before this, someone arriving from the repository had no way to know
  `composer require langacorp/kemproof` existed.
- README: says what Composer installs and what it does not — `liboqs` is a
  system library and has to be there already.

## v1.1.0 — 2026-09-03

Tagged, never released: there is no GitHub release for this tag, so this
version is not archived on Zenodo.

- README: point to the other five tools, and say what this one is not.
- composer.json: make the PHP library installable.

## v1.0.0 — 2026-08-30

- kemproof: attest an ML-KEM-768 key exchange, and say only what that proves

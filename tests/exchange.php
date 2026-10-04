<?php
declare(strict_types=1);
/**
 * A genuine ML-KEM-768 exchange through KemAttestation, against liboqs.
 *
 * Needs the shared library: set KEMPROOF_LIBOQS to its path. Without it this
 * script says it did not run and exits 0, so a run without liboqs is never
 * read as a run that passed with it.
 *
 * The prover side is played here with OQS_KEM_encaps, declared by this test.
 * The fingerprint is then recomputed from the prover's own shared secret, so
 * the check is that both sides reached the same secret, not only that
 * attest() returned something.
 */
require __DIR__ . '/../src/KemAttestation.php';

$lib = (string) \getenv('KEMPROOF_LIBOQS');
if ($lib === '' || !\is_file($lib)) {
    echo "exchange: NOT RUN — KEMPROOF_LIBOQS does not point to liboqs\n";
    exit(0);
}

final class MemoryStore implements KemProof\StoreInterface
{
    /** @var array<string,array> */
    public array $records = [];
    public function put(string $subject, array $record): void { $this->records[$subject] = $record; }
    public function get(string $subject): ?array { return $this->records[$subject] ?? null; }
}

$prover = FFI::cdef(<<<'C'
typedef struct OQS_KEM OQS_KEM;
OQS_KEM *OQS_KEM_new(const char *method_name);
int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
void OQS_KEM_free(OQS_KEM *kem);
C, $lib);

/** @return array{0:string,1:string} ciphertext, shared secret */
function encapsulate(FFI $ffi, string $pk): array
{
    $kem = $ffi->OQS_KEM_new('ML-KEM-768');
    if ($kem === null) { throw new RuntimeException('OQS_KEM_new failed'); }
    try {
        $pkb = FFI::new('uint8_t[1184]');
        $ct  = FFI::new('uint8_t[1088]');
        $ss  = FFI::new('uint8_t[32]');
        FFI::memcpy($pkb, $pk, 1184);
        if ($ffi->OQS_KEM_encaps($kem, $ct, $ss, $pkb) !== 0) { throw new RuntimeException('encaps failed'); }
        return [FFI::string($ct, 1088), FFI::string($ss, 32)];
    } finally {
        $ffi->OQS_KEM_free($kem);
    }
}

$fail = 0;
function check(string $label, bool $ok): void
{
    global $fail;
    printf("  %-60s %s\n", $label, $ok ? 'ok' : 'FAIL');
    if (!$ok) { $fail++; }
}

$store = new MemoryStore();
$kem   = new KemProof\KemAttestation($lib, $store, 3600);

$hs = $kem->handshake();
check('handshake: public key is 1184 bytes', \strlen($hs['public_key']) === 1184);
check('handshake: secret key is 2400 bytes', \strlen($hs['secret_key']) === 2400);
check('handshake: session id is 32 hex chars', (bool) \preg_match('/^[0-9a-f]{32}$/', $hs['session_id']));
check('handshake: two calls give two different keypairs', $kem->handshake()['public_key'] !== $hs['public_key']);

[$ct, $proverSecret] = encapsulate($prover, $hs['public_key']);
$record = $kem->attest('host.example.com', $hs['session_id'], $hs['secret_key'], $ct);
$expect = \hash_hmac('sha256', $proverSecret, $hs['session_id']);

check('attest: fingerprint matches the prover\'s shared secret', \hash_equals($expect, $record['fingerprint']));
check('attest: record names ML-KEM-768 and FIPS 203', $record['algorithm'] === 'ML-KEM-768' && $record['standard'] === 'NIST FIPS 203');
check('attest: expires ttl seconds after it was attested', $record['expires_at'] - $record['attested_at'] === 3600);
check('attest: the shared secret is not in the record', \strpos(\serialize($record), $proverSecret) === false);
check('store: the record was stored under the subject', $store->get('host.example.com') === $record);

$status = $kem->status('host.example.com');
check('status: valid while not expired', $status !== null && $status['valid'] === true);
check('status: null for a subject never attested', $kem->status('never.example.com') === null);

// The other direction for status: an expired record must say valid => false.
$expired = new KemProof\KemAttestation($lib, $store, -1);
$expired->attest('stale.example.com', $hs['session_id'], $hs['secret_key'], $ct);
$s = $kem->status('stale.example.com');
check('status: expired record is present and valid => false', $s !== null && $s['valid'] === false);

// The other direction for the fingerprint: a different session id, or a
// ciphertext with one bit flipped, must not reproduce it.
$other = $kem->attest('h2.example.com', \str_repeat('0', 32), $hs['secret_key'], $ct);
check('fingerprint: a different session id gives a different one', $other['fingerprint'] !== $record['fingerprint']);
$flipped = $ct;
$flipped[0] = \chr(\ord($flipped[0]) ^ 1);
$tampered = $kem->attest('h3.example.com', $hs['session_id'], $hs['secret_key'], $flipped);
check('fingerprint: a flipped ciphertext bit gives a different one', $tampered['fingerprint'] !== $record['fingerprint']);

// Measured, not a pass/fail: ML-KEM decapsulation uses implicit rejection.
// A tampered or random ciphertext decapsulates "successfully" to a
// pseudo-random secret, so attest() stores a record for it. See README.
echo '  note: tampered ciphertext was attested too, valid => ',
    \var_export($kem->status('h3.example.com')['valid'], true), " (implicit rejection)\n";

echo $fail === 0 ? "\nexchange: a real ML-KEM-768 exchange completes and the fingerprint matches\n" : "\n$fail exchange check(s) failed\n";
exit($fail === 0 ? 0 : 1);

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
 * The prover computes its key confirmation from its own shared secret, and
 * the fingerprint is recomputed from that same secret, so the check is that
 * both sides reached the same secret, not only that attest() returned.
 *
 * Every acceptance check has its refusal next to it: a tampered or random
 * ciphertext, a confirmation moved to another subject or session, a
 * confirmation made with the wrong secret. Each must throw and store nothing.
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
$K     = KemProof\KemAttestation::class;

/** attest() that reports the refusal instead of throwing it. */
function refused(callable $f): ?string
{
    try { $f(); return null; } catch (RuntimeException $e) { return $e->getMessage(); }
}

$hs = $kem->handshake();
check('handshake: public key is 1184 bytes', \strlen($hs['public_key']) === 1184);
check('handshake: secret key is 2400 bytes', \strlen($hs['secret_key']) === 2400);
check('handshake: session id is 32 hex chars', (bool) \preg_match('/^[0-9a-f]{32}$/', $hs['session_id']));
check('handshake: two calls give two different keypairs', $kem->handshake()['public_key'] !== $hs['public_key']);
check('handshake: the public key sits inside the secret key (FIPS 203)',
    \substr($hs['secret_key'], 1152, 1184) === $hs['public_key']);

$subject = 'host.example.com';
[$ct, $proverSecret] = encapsulate($prover, $hs['public_key']);
$confirm = $K::confirmation($proverSecret, $hs['session_id'], $subject, $hs['public_key'], $ct);
check('confirmation: 32 bytes', \strlen($confirm) === 32);

$record = $kem->attest($subject, $hs['session_id'], $hs['secret_key'], $ct, $confirm);
$expect = \hash_hmac('sha256', $proverSecret, $hs['session_id']);

check('attest: fingerprint matches the prover\'s shared secret', \hash_equals($expect, $record['fingerprint']));
check('attest: record says protocol kemproof/2, confirmed', $record['protocol'] === 'kemproof/2' && $record['confirmed'] === true);
check('attest: record names ML-KEM-768 and FIPS 203', $record['algorithm'] === 'ML-KEM-768' && $record['standard'] === 'NIST FIPS 203');
check('attest: expires ttl seconds after it was attested', $record['expires_at'] - $record['attested_at'] === 3600);
check('attest: the shared secret is not in the record', \strpos(\serialize($record), $proverSecret) === false);
check('store: the record was stored under the subject', $store->get($subject) === $record);

$status = $kem->status($subject);
check('status: valid while not expired', $status !== null && $status['valid'] === true);
check('status: null for a subject never attested', $kem->status('never.example.com') === null);

$expired = new KemProof\KemAttestation($lib, $store, -1);
$expired->attest('stale.example.com', $hs['session_id'], $hs['secret_key'], $ct,
    $K::confirmation($proverSecret, $hs['session_id'], 'stale.example.com', $hs['public_key'], $ct));
$s = $kem->status('stale.example.com');
check('status: expired record is present and valid => false', $s !== null && $s['valid'] === false);

// --- The direction that must fail. Each case: refused, and nothing stored.
$before = $store->records;
$flipped = $ct;
$flipped[0] = \chr(\ord($flipped[0]) ^ 1);
$cases = [
    'a ciphertext with one bit flipped' => [$subject, $hs['session_id'], $flipped, $confirm],
    'a random ciphertext (implicit rejection)' => [$subject, $hs['session_id'], \random_bytes(1088), $confirm],
    'a confirmation moved to another subject' => ['other.example.com', $hs['session_id'], $ct, $confirm],
    'a confirmation moved to another session' => [$subject, \str_repeat('0', 32), $ct, $confirm],
    'a confirmation made with a wrong secret' => [$subject, $hs['session_id'], $ct,
        $K::confirmation(\random_bytes(32), $hs['session_id'], $subject, $hs['public_key'], $ct)],
    'a confirmation of zeros' => [$subject, $hs['session_id'], $ct, \str_repeat("\0", 32)],
];
foreach ($cases as $label => [$sub, $sid, $c, $conf]) {
    $why = refused(fn () => $kem->attest($sub, $sid, $hs['secret_key'], $c, $conf));
    check("refused: $label", $why !== null && \strpos($why, 'key confirmation failed') === 0);
}
// Another keypair's secret key: its public key differs, so the transcript does.
$hs2 = $kem->handshake();
$why = refused(fn () => $kem->attest($subject, $hs['session_id'], $hs2['secret_key'], $ct, $confirm));
check('refused: the ciphertext presented to another keypair', $why !== null && \strpos($why, 'key confirmation failed') === 0);
check('refused: nothing was stored by any refused attempt', $store->records === $before);

echo $fail === 0 ? "\nexchange: a real ML-KEM-768 exchange completes, the prover is confirmed, and every forgery is refused\n" : "\n$fail exchange check(s) failed\n";
exit($fail === 0 ? 0 : 1);

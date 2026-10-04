<?php
declare(strict_types=1);

namespace KemProof;

use FFI;
use RuntimeException;

// Composer finds StoreInterface through PSR-4 on its own. This line keeps a
// plain require of this file working, as it did before the interface moved.
require_once __DIR__ . '/StoreInterface.php';

/**
 * kemproof — attest that an ML-KEM-768 key exchange really happened.
 *
 * This does NOT protect a channel. It produces a record: an exchange took
 * place, with this algorithm, at this time, valid until then. Read the README
 * before deciding whether that is what you need.
 *
 * Protocol 2: the prover must show it holds the same shared secret, with a
 * key confirmation bound to the session, the subject, the public key and the
 * ciphertext. Without it, ML-KEM's implicit rejection lets any ciphertext of
 * the right size "decapsulate" and be recorded.
 */
final class KemAttestation
{
    public const ALG      = 'ML-KEM-768';
    public const PROTOCOL = 'kemproof/2';

    // ML-KEM-768 sizes, NIST FIPS 203
    private const PK_LEN = 1184;
    private const SK_LEN = 2400;
    private const CT_LEN = 1088;
    private const SS_LEN = 32;

    // FIPS 203 decapsulation key: dk_PKE (384*k = 1152) || ek || H(ek) || z.
    // The public key the ciphertext was made for is inside the secret key.
    private const SK_PK_OFFSET = 1152;

    public const CONFIRMATION_LEN = 32;
    private const CONFIRMATION_LABEL = 'kemproof/2 key confirmation';

    private const CDEF = <<<'C'
typedef struct OQS_KEM OQS_KEM;
OQS_KEM *OQS_KEM_new(const char *method_name);
int OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *pk, uint8_t *sk);
int OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
void OQS_KEM_free(OQS_KEM *kem);
C;

    private ?FFI $ffi = null;
    private string $libPath;
    private StoreInterface $store;
    private int $ttl;

    /**
     * @param string $libPath path to liboqs shared library
     * @param int    $ttl     how long an attestation stays valid, in seconds
     */
    public function __construct(string $libPath, StoreInterface $store, int $ttl = 86400)
    {
        $this->libPath = $libPath;
        $this->store   = $store;
        $this->ttl     = $ttl;
    }

    private function ffi(): FFI
    {
        if ($this->ffi !== null) {
            return $this->ffi;
        }
        if (!\extension_loaded('ffi') || !\is_file($this->libPath)) {
            throw new RuntimeException('liboqs not available at ' . $this->libPath);
        }
        try {
            return $this->ffi = FFI::cdef(self::CDEF, $this->libPath);
        } catch (\FFI\Exception $e) {
            // Under PHP-FPM or the built-in server the default ffi.enable=preload
            // forbids FFI::cdef(): say so instead of surfacing an FFI error.
            throw new RuntimeException(
                'liboqs could not be loaded through FFI (' . $e->getMessage() . '); '
                . 'outside the CLI, ffi.enable must be "true" or the library preloaded'
            );
        }
    }

    /**
     * Step 1 — create a keypair, hand out the public key.
     *
     * The secret key comes back to the caller, who keeps it on the server and
     * uses it for ONE attest() call, then deletes it, whatever the outcome.
     * Never send it to the prover.
     */
    public function handshake(): array
    {
        $ffi = $this->ffi();
        $kem = $ffi->OQS_KEM_new(self::ALG);
        if ($kem === null) {
            throw new RuntimeException('OQS_KEM_new failed');
        }
        $pk = FFI::new('uint8_t[' . self::PK_LEN . ']');
        $sk = FFI::new('uint8_t[' . self::SK_LEN . ']');
        try {
            if ($ffi->OQS_KEM_keypair($kem, $pk, $sk) !== 0) {
                throw new RuntimeException('keypair failed');
            }
            return [
                'session_id'   => \bin2hex(\random_bytes(16)),
                'public_key'   => FFI::string($pk, self::PK_LEN),
                'secret_key'   => FFI::string($sk, self::SK_LEN),
            ];
        } finally {
            FFI::memset($sk, 0, self::SK_LEN);
            $ffi->OQS_KEM_free($kem);
        }
    }

    /**
     * The value a prover sends to show it holds the shared secret.
     *
     * HMAC-SHA256 keyed with the shared secret, over a transcript that binds
     * the session, the subject, the public key and the ciphertext. The client
     * in client/attest.py computes the same bytes; tests/vector.* pin them.
     */
    public static function confirmation(
        string $sharedSecret,
        string $sessionId,
        string $subject,
        string $publicKey,
        string $ciphertext
    ): string {
        $transcript = self::lp(self::CONFIRMATION_LABEL)
            . self::lp($sessionId)
            . self::lp($subject)
            . self::lp(\hash('sha256', $publicKey, true))
            . self::lp(\hash('sha256', $ciphertext, true));
        return \hash_hmac('sha256', $transcript, $sharedSecret, true);
    }

    /** Length-prefixed field: no two transcripts can be read the same way. */
    private static function lp(string $field): string
    {
        return \pack('N', \strlen($field)) . $field;
    }

    /**
     * Step 2 — the prover encapsulated against our public key and sent back
     * the ciphertext and its key confirmation. We decapsulate, check that the
     * prover reached the same secret, store a fingerprint, discard the secret.
     *
     * A wrong confirmation throws and stores nothing: a ciphertext that was
     * not produced against this public key, or one moved to another subject
     * or session, is refused instead of recorded.
     */
    public function attest(
        string $subject,
        string $sessionId,
        string $secretKey,
        string $ciphertext,
        string $confirmation
    ): array {
        if (\strlen($ciphertext) !== self::CT_LEN) {
            throw new RuntimeException('ciphertext must be ' . self::CT_LEN . ' bytes');
        }
        // decapsulate() copies exactly SK_LEN bytes: a longer key would be cut
        // without a word, a shorter one would fail inside FFI.
        if (\strlen($secretKey) !== self::SK_LEN) {
            throw new RuntimeException('secret key must be ' . self::SK_LEN . ' bytes');
        }
        if (\strlen($confirmation) !== self::CONFIRMATION_LEN) {
            throw new RuntimeException('confirmation must be ' . self::CONFIRMATION_LEN . ' bytes');
        }
        $publicKey = \substr($secretKey, self::SK_PK_OFFSET, self::PK_LEN);

        $shared = $this->decapsulate($secretKey, $ciphertext);
        try {
            $expected = self::confirmation($shared, $sessionId, $subject, $publicKey, $ciphertext);
            if (!\hash_equals($expected, $confirmation)) {
                throw new RuntimeException(
                    'key confirmation failed: the prover did not show the same shared secret'
                );
            }
            $fingerprint = \hash_hmac('sha256', $shared, $sessionId);
        } finally {
            self::wipe($shared);
        }

        $now = \time();
        $record = [
            'subject'     => $subject,
            'algorithm'   => self::ALG,
            'standard'    => 'NIST FIPS 203',
            'protocol'    => self::PROTOCOL,
            'confirmed'   => true,
            'fingerprint' => $fingerprint,
            'attested_at' => $now,
            'expires_at'  => $now + $this->ttl,
        ];
        $this->store->put($subject, $record);
        return $record;
    }

    private function decapsulate(string $secretKey, string $ciphertext): string
    {
        $ffi = $this->ffi();
        $kem = $ffi->OQS_KEM_new(self::ALG);
        if ($kem === null) {
            throw new RuntimeException('OQS_KEM_new failed');
        }
        $sk = FFI::new('uint8_t[' . self::SK_LEN . ']');
        $ct = FFI::new('uint8_t[' . self::CT_LEN . ']');
        $ss = FFI::new('uint8_t[' . self::SS_LEN . ']');
        try {
            FFI::memcpy($sk, $secretKey, self::SK_LEN);
            FFI::memcpy($ct, $ciphertext, self::CT_LEN);
            if ($ffi->OQS_KEM_decaps($kem, $ss, $ct, $sk) !== 0) {
                throw new RuntimeException('decapsulation failed');
            }
            return FFI::string($ss, self::SS_LEN);
        } finally {
            FFI::memset($sk, 0, self::SK_LEN);
            FFI::memset($ss, 0, self::SS_LEN);
            $ffi->OQS_KEM_free($kem);
        }
    }

    /**
     * Best effort: PHP strings can be copied by the engine, so this clears
     * the copy we hold, not every copy that ever existed.
     */
    private static function wipe(string &$secret): void
    {
        if (\function_exists('sodium_memzero')) {
            \sodium_memzero($secret);
        } else {
            $secret = \str_repeat("\0", \strlen($secret));
        }
    }

    /**
     * Step 3 — what can be said about a subject, and until when.
     * Returns null when nothing was ever attested, which is different from
     * an attestation that has expired.
     */
    public function status(string $subject): ?array
    {
        $record = $this->store->get($subject);
        if ($record === null) {
            return null;
        }
        $record['valid'] = $record['expires_at'] > \time();
        return $record;
    }
}

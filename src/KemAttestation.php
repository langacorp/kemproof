<?php
declare(strict_types=1);

namespace KemProof;

use FFI;
use RuntimeException;

/**
 * kemproof — attest that an ML-KEM-768 key exchange really happened.
 *
 * This does NOT protect a channel. It produces a record: an exchange took
 * place, with this algorithm, at this time, valid until then. Read the README
 * before deciding whether that is what you need.
 */
final class KemAttestation
{
    public const ALG = 'ML-KEM-768';

    // ML-KEM-768 sizes, NIST FIPS 203
    private const PK_LEN = 1184;
    private const SK_LEN = 2400;
    private const CT_LEN = 1088;
    private const SS_LEN = 32;

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
        return $this->ffi = FFI::cdef(self::CDEF, $this->libPath);
    }

    /** Step 1 — create a keypair, hand out the public key. */
    public function handshake(): array
    {
        $ffi = $this->ffi();
        $kem = $ffi->OQS_KEM_new(self::ALG);
        if ($kem === null) {
            throw new RuntimeException('OQS_KEM_new failed');
        }
        try {
            $pk = FFI::new('uint8_t[' . self::PK_LEN . ']');
            $sk = FFI::new('uint8_t[' . self::SK_LEN . ']');
            if ($ffi->OQS_KEM_keypair($kem, $pk, $sk) !== 0) {
                throw new RuntimeException('keypair failed');
            }
            return [
                'session_id'   => \bin2hex(\random_bytes(16)),
                'public_key'   => FFI::string($pk, self::PK_LEN),
                'secret_key'   => FFI::string($sk, self::SK_LEN),
            ];
        } finally {
            $ffi->OQS_KEM_free($kem);
        }
    }

    /**
     * Step 2 — the prover encapsulated against our public key. We decapsulate,
     * derive a fingerprint of the shared secret, store it, discard the secret.
     */
    public function attest(string $subject, string $sessionId, string $secretKey, string $ciphertext): array
    {
        if (\strlen($ciphertext) !== self::CT_LEN) {
            throw new RuntimeException('ciphertext must be ' . self::CT_LEN . ' bytes');
        }
        $shared = $this->decapsulate($secretKey, $ciphertext);
        $record = [
            'subject'     => $subject,
            'algorithm'   => self::ALG,
            'standard'    => 'NIST FIPS 203',
            'fingerprint' => \hash_hmac('sha256', $shared, $sessionId),
            'attested_at' => \time(),
            'expires_at'  => \time() + $this->ttl,
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
        try {
            $sk = FFI::new('uint8_t[' . self::SK_LEN . ']');
            $ct = FFI::new('uint8_t[' . self::CT_LEN . ']');
            $ss = FFI::new('uint8_t[' . self::SS_LEN . ']');
            FFI::memcpy($sk, $secretKey, self::SK_LEN);
            FFI::memcpy($ct, $ciphertext, self::CT_LEN);
            if ($ffi->OQS_KEM_decaps($kem, $ss, $ct, $sk) !== 0) {
                throw new RuntimeException('decapsulation failed');
            }
            return FFI::string($ss, self::SS_LEN);
        } finally {
            $ffi->OQS_KEM_free($kem);
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

/** Where attestations live. Bring your own: a table, a file, a cache. */
interface StoreInterface
{
    public function put(string $subject, array $record): void;

    /** @return array<string,mixed>|null null when the subject was never attested */
    public function get(string $subject): ?array;
}

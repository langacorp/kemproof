#!/usr/bin/env python3
"""
kemproof client — prove to a verifier that you ran an ML-KEM-768
encapsulation against its public key, so it can record that the exchange
happened.

Protocol kemproof/2: next to the ciphertext the client sends a key
confirmation, an HMAC keyed with the shared secret over the session, the
subject, the public key and the ciphertext. The verifier recomputes it from
the secret it decapsulated and refuses the exchange if the two differ.

Needs liboqs. The shared secret is used for the confirmation and then
cleared: this side does not keep it either.
"""
import base64
import ctypes
import hashlib
import hmac
import json
import struct
import sys
import urllib.parse
import urllib.request

ALG = b"ML-KEM-768"
PK_LEN, CT_LEN, SS_LEN = 1184, 1088, 32
PROTOCOL = "kemproof/2"
CONFIRMATION_LABEL = b"kemproof/2 key confirmation"


def _lp(field):
    """Length-prefixed field, 4-byte big-endian length: same as PHP pack('N')."""
    return struct.pack(">I", len(field)) + field


def confirmation(shared_secret, session_id, subject, public_key, ciphertext):
    """The 32 bytes the verifier expects. Must match KemAttestation::confirmation()."""
    def b(x):
        return x if isinstance(x, bytes) else x.encode("utf-8")
    transcript = (_lp(CONFIRMATION_LABEL) + _lp(b(session_id)) + _lp(b(subject))
                  + _lp(hashlib.sha256(public_key).digest())
                  + _lp(hashlib.sha256(ciphertext).digest()))
    return hmac.new(shared_secret, transcript, hashlib.sha256).digest()


def load(lib_path):
    lib = ctypes.CDLL(lib_path)
    lib.OQS_KEM_new.restype = ctypes.c_void_p
    lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
    lib.OQS_KEM_encaps.restype = ctypes.c_int
    lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint8)] * 3
    lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
    return lib


def encapsulate(lib, public_key):
    """Returns (ciphertext, shared_secret). The liboqs buffer holding the
    secret is cleared here; the bytes copy lives until attest() drops it."""
    if len(public_key) != PK_LEN:
        raise ValueError("public key must be %d bytes" % PK_LEN)
    kem = lib.OQS_KEM_new(ALG)
    if not kem:
        raise RuntimeError("OQS_KEM_new failed")
    try:
        pk = (ctypes.c_uint8 * PK_LEN)(*public_key)
        ct = (ctypes.c_uint8 * CT_LEN)()
        ss = (ctypes.c_uint8 * SS_LEN)()
        try:
            if lib.OQS_KEM_encaps(kem, ct, ss, pk) != 0:
                raise RuntimeError("encapsulation failed")
            return bytes(ct), bytes(ss)
        finally:
            ctypes.memset(ss, 0, SS_LEN)
    finally:
        lib.OQS_KEM_free(kem)


def get_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def attest(base_url, subject, lib_path):
    """Run one full exchange. Returns the record the verifier stored."""
    lib = load(lib_path)
    hs = get_json("%s/handshake?%s" % (base_url.rstrip("/"),
                                       urllib.parse.urlencode({"subject": subject})))
    public_key = base64.b64decode(hs["public_key"])
    ciphertext, shared = encapsulate(lib, public_key)
    confirm = confirmation(shared, hs["session_id"], subject, public_key, ciphertext)
    del shared
    return get_json("%s/attest" % base_url.rstrip("/"), {
        "subject": subject,
        "session_id": hs["session_id"],
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "confirmation": base64.b64encode(confirm).decode(),
    })


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: attest.py <base-url> <subject> <path-to-liboqs.so>",
              file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(attest(sys.argv[1], sys.argv[2], sys.argv[3]), indent=2))

#!/usr/bin/env python3
"""
kemproof client — prove to a verifier that you can run an ML-KEM-768
encapsulation, so it can record that the exchange happened.

Needs liboqs. The shared secret is derived here and thrown away: this side
does not keep it either.
"""
import base64
import ctypes
import json
import sys
import urllib.request

ALG = b"ML-KEM-768"
PK_LEN, CT_LEN, SS_LEN = 1184, 1088, 32


def load(lib_path):
    lib = ctypes.CDLL(lib_path)
    lib.OQS_KEM_new.restype = ctypes.c_void_p
    lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
    lib.OQS_KEM_encaps.restype = ctypes.c_int
    lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint8)] * 3
    lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
    return lib


def encapsulate(lib, public_key):
    if len(public_key) != PK_LEN:
        raise ValueError("public key must be %d bytes" % PK_LEN)
    kem = lib.OQS_KEM_new(ALG)
    if not kem:
        raise RuntimeError("OQS_KEM_new failed")
    try:
        pk = (ctypes.c_uint8 * PK_LEN)(*public_key)
        ct = (ctypes.c_uint8 * CT_LEN)()
        ss = (ctypes.c_uint8 * SS_LEN)()
        if lib.OQS_KEM_encaps(kem, ct, ss, pk) != 0:
            raise RuntimeError("encapsulation failed")
        return bytes(ct)
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
    hs = get_json("%s/handshake?subject=%s" % (base_url.rstrip("/"), subject))
    ciphertext = encapsulate(lib, base64.b64decode(hs["public_key"]))
    return get_json("%s/attest" % base_url.rstrip("/"), {
        "subject": subject,
        "session_id": hs["session_id"],
        "ciphertext": base64.b64encode(ciphertext).decode(),
    })


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: attest.py <base-url> <subject> <path-to-liboqs.so>",
              file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(attest(sys.argv[1], sys.argv[2], sys.argv[3]), indent=2))

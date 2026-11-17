#!/usr/bin/env python3
r"""
Verify that an APK is signed by the official NagramXF release key.

Reads the APK Signature Scheme v2 block straight out of the file (no Android
SDK needed) and compares the signer certificate against an expected SHA-256.

Reference value, measured from the official GitHub release asset
NagramXF-v12.10.1-30dcd6c.1251.-normal-armeabi-v7a.apk and from the keystore
committed at TMessagesProj/release.keystore in the upstream repo (they are
byte-identical):

    1a05a230b7d3c4703c79a5baf872396112669c4d716474be6f9e8247a54c4563

Usage:
    python3 verify_signer.py <apk> [expected_sha256_hex]

Exits 0 when the signer matches, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import struct
import sys

DEFAULT_EXPECTED = "1a05a230b7d3c4703c79a5baf872396112669c4d716474be6f9e8247a54c4563"
MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def read_signing_block(data: bytes) -> tuple[int, int]:
    i = data.rfind(MAGIC)
    if i < 0:
        raise ValueError("APK Signing Block magic not found - APK is not v2/v3 signed")
    size = struct.unpack("<Q", data[i - 8 : i])[0]
    block_start = i + 8 - size          # the block length covers header, pairs AND magic
    if struct.unpack("<Q", data[block_start : block_start + 8])[0] != size:
        raise ValueError("APK Signing Block size fields disagree - truncated file?")
    return block_start + 8, i - 8       # first pair .. last pair


def iter_pairs(data: bytes, start: int, end: int):
    off = start
    while off < end:
        (pair_len,) = struct.unpack("<Q", data[off : off + 8])
        (pair_id,) = struct.unpack("<I", data[off + 8 : off + 12])
        yield pair_id, off + 12, pair_len - 4
        off += 8 + pair_len


def seq(data: bytes, off: int) -> tuple[int, int]:
    (n,) = struct.unpack("<I", data[off : off + 4])
    return off + 4, n


def extract_signer_certs(data: bytes, block_id: int) -> list[bytes]:
    """Pull every signer certificate out of one signature-scheme block."""
    start, end = read_signing_block(data)
    for pid, body, _len in iter_pairs(data, start, end):
        if pid != block_id:
            continue
        off, _ = seq(data, body)                 # signers          (sequence)
        off, _ = seq(data, off)                  # signer[0]        (sequence)
        signed_off, _ = seq(data, off)           # signed data      (sequence)
        dig_off, dig_len = seq(data, signed_off)  # digests          (sequence)
        certs_hdr_off = dig_off + dig_len
        certs_off, certs_len = seq(data, certs_hdr_off)  # certificates (sequence)
        certs_end = certs_off + certs_len
        out: list[bytes] = []
        while certs_off < certs_end:
            c_off, c_len = seq(data, certs_off)  # certificate[i]   (byte string)
            out.append(data[c_off : c_off + c_len])
            certs_off = c_off + c_len
        if out:
            return out
    return []


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    expected = (sys.argv[2] if len(sys.argv) > 2 else DEFAULT_EXPECTED).lower().replace(":", "")

    data = open(path, "rb").read()
    certs: list[bytes] = []
    for scheme, name in ((V2_BLOCK_ID, "v2"), (V3_BLOCK_ID, "v3")):
        try:
            found = extract_signer_certs(data, scheme)
        except ValueError as exc:
            print(f"{name}: {exc}")
            continue
        if found:
            print(f"{name}: {len(found)} signer certificate(s)")
            certs.extend(found)

    if not certs:
        print("FAIL: could not extract any signer certificate")
        return 1

    digests = {hashlib.sha256(c).hexdigest() for c in certs}
    for d in sorted(digests):
        mark = "MATCH" if d == expected else "differs"
        print(f"  sha256={d}  [{mark}]")

    if expected in digests:
        print("OK: signed by the expected NagramXF release key")
        return 0
    print("FAIL: signer does NOT match the expected key - do not install over your current app")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

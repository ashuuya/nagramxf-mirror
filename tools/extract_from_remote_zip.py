#!/usr/bin/env python3
r"""
Extract ONE file from a remote ZIP using HTTP Range requests only.

Why this exists
---------------
GitHub Actions artifacts for NagramXF are published as a single ZIP that holds
4 APKs (arm64-v8a / armeabi-v7a / universal / x86_64) and is ~265 MB.
Downloading the whole ZIP just to republish one 59 MB APK wastes bandwidth and
GitHub Release storage. This script reads only:

  * the last 64 KiB  -> End Of Central Directory (EOCD)
  * the central directory (~1.4 KiB)
  * the local file header of the wanted entry (~100 B)
  * the compressed bytes of the wanted entry (~59 MB)

...and writes a valid standalone ZIP containing just that one file.

The remote server must support Range requests. Both GitHub's artifact blob
storage (productionresultssa*.blob.core.windows.net) and nightly.link do.

Usage
-----
    python3 extract_from_remote_zip.py <zip-url> <filename-regex> <out.zip>

Example
-------
    python3 extract_from_remote_zip.py \
        "https://nightly.link/Keeperorowner/NagramXF/workflows/staging.yml/dev/normal-staging.zip" \
        'normal-arm64-v8a\.apk$' \
        out.zip
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import struct
import sys
import urllib.request
import zipfile

USER_AGENT = "nagramxf-artifact-fetcher/1.0"
EOCD_SIZE = 65536 + 22  # max comment (65535) + EOCD record (22)
ZIP64_EOCD_SIZE = 76


class RangeReader:
    """Minimal HTTP range reader that follows redirects once and reuses the final URL."""

    def __init__(self, url: str, timeout: int = 120):
        self.opener = urllib.request.build_opener()
        self.timeout = timeout
        # Resolve redirects once up-front so later Range requests hit the blob directly.
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"})
        with self.opener.open(req, timeout=timeout) as resp:
            self.url = resp.geturl()
            resp.read(1)

    def read(self, start: int | None = None, end: int | None = None, tail: int | None = None) -> bytes:
        headers = {"User-Agent": USER_AGENT}
        if tail is not None:
            headers["Range"] = f"bytes=-{tail}"
        elif start is not None:
            headers["Range"] = f"bytes={start}-{end}" if end is not None else f"bytes={start}-"
        req = urllib.request.Request(self.url, headers=headers)
        with self.opener.open(req, timeout=self.timeout) as resp:
            return resp.read()


def find_eocd(tail: bytes) -> tuple[int, int, int, bool]:
    """Return (total_entries, cd_size, cd_offset, is_zip64) from a tail-of-file buffer."""
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise SystemExit("EOCD signature not found - is this really a ZIP?")
    total, cd_size, cd_off = struct.unpack("<HII", tail[i + 10 : i + 20])

    zip64 = 0xFFFF in (total,) or 0xFFFFFFFF in (cd_size, cd_off)
    if zip64:
        j = tail.rfind(b"PK\x06\x06")
        if j < 0:
            raise SystemExit("ZIP64 EOCD required but not found")
        total = struct.unpack("<Q", tail[j + 32 : j + 40])[0]
        cd_size = struct.unpack("<Q", tail[j + 40 : j + 48])[0]
        cd_off = struct.unpack("<Q", tail[j + 48 : j + 56])[0]
    return total, cd_size, cd_off, zip64


def parse_central_directory(cd: bytes) -> list[dict]:
    entries: list[dict] = []
    i = 0
    while i + 46 <= len(cd) and cd[i : i + 4] == b"PK\x01\x02":
        (method,) = struct.unpack("<H", cd[i + 10 : i + 12])
        comp_size, uncomp_size = struct.unpack("<II", cd[i + 20 : i + 28])
        name_len, extra_len, comment_len = struct.unpack("<HHH", cd[i + 28 : i + 34])
        (local_header_off,) = struct.unpack("<I", cd[i + 42 : i + 46])
        name = cd[i + 46 : i + 46 + name_len].decode("utf-8", "replace")

        # ZIP64 extra field may carry the real sizes / offset.
        extra = cd[i + 46 + name_len : i + 46 + name_len + extra_len]
        k = 0
        while k + 4 <= len(extra):
            tag, size = struct.unpack("<HH", extra[k : k + 4])
            if tag == 0x0001:
                vals = extra[k + 4 : k + 4 + size]
                p = 0
                if uncomp_size == 0xFFFFFFFF:
                    uncomp_size = struct.unpack("<Q", vals[p : p + 8])[0]
                    p += 8
                if comp_size == 0xFFFFFFFF:
                    comp_size = struct.unpack("<Q", vals[p : p + 8])[0]
                    p += 8
                if local_header_off == 0xFFFFFFFF:
                    local_header_off = struct.unpack("<Q", vals[p : p + 8])[0]
                break
            k += 4 + size

        entries.append(
            {
                "name": name,
                "method": method,
                "comp_size": comp_size,
                "uncomp_size": uncomp_size,
                "local_header_off": local_header_off,
                "crc": struct.unpack("<I", cd[i + 16 : i + 20])[0],
            }
        )
        i += 46 + name_len + extra_len + comment_len
    return entries


def build_single_file_zip(name: str, payload: bytes, method: int, crc: int, uncomp_size: int) -> bytes:
    """Wrap already-compressed bytes into a valid standalone ZIP (no recompression)."""
    if method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise SystemExit(f"unsupported compression method {method}")
    comp_size = len(payload)
    name_b = name.encode("utf-8")

    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, method, 0, 0, crc, comp_size, uncomp_size, len(name_b), 0
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, method, 0, 0, crc, comp_size, uncomp_size,
        len(name_b), 0, 0, 0, 0, 0, 0,
    )
    cd_offset = len(local) + len(name_b) + comp_size
    cd_block = central + name_b          # the file name MUST follow the central header
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd_block), cd_offset, 0
    )
    return local + name_b + payload + cd_block + eocd


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zip_url", help="URL of the remote ZIP (may redirect)")
    ap.add_argument("pattern", help="Regex matched against entry names; first match wins")
    ap.add_argument("out_zip", help="Output ZIP path (will contain exactly one file)")
    ap.add_argument("--list", action="store_true", help="Only list entries, extract nothing")
    args = ap.parse_args()

    rx = re.compile(args.pattern)
    r = RangeReader(args.zip_url)
    print(f"resolved URL host: {r.url.split('/')[2]}", file=sys.stderr)

    tail = r.read(tail=EOCD_SIZE)
    total, cd_size, cd_off, zip64 = find_eocd(tail)
    print(f"entries={total} cd_offset={cd_off} cd_size={cd_size} zip64={zip64}", file=sys.stderr)

    cd = r.read(cd_off, cd_off + cd_size - 1)
    entries = parse_central_directory(cd)

    if args.list:
        for e in entries:
            print(f"{e['name']}\t{e['comp_size']}\t{e['uncomp_size']}\tmethod={e['method']}")
        return 0

    match = next((e for e in entries if rx.search(e["name"])), None)
    if match is None:
        print("Available entries:", file=sys.stderr)
        for e in entries:
            print("  " + e["name"], file=sys.stderr)
        raise SystemExit(f"no entry matches {args.pattern!r}")

    e = match
    print(f"selected: {e['name']} ({e['comp_size']/1e6:.1f} MB compressed)", file=sys.stderr)

    lh = r.read(e["local_header_off"], e["local_header_off"] + 29)
    if lh[:4] != b"PK\x03\x04":
        raise SystemExit("bad local file header signature")
    name_len, extra_len = struct.unpack("<HH", lh[26:30])
    data_off = e["local_header_off"] + 30 + name_len + extra_len

    # Stream the payload so peak memory stays at one chunk instead of the whole APK.
    buf = io.BytesIO()
    remaining = e["comp_size"]
    pos = data_off
    chunk = 8 * 1024 * 1024
    while remaining > 0:
        n = min(chunk, remaining)
        buf.write(r.read(pos, pos + n - 1))
        pos += n
        remaining -= n
        print(f"  fetched {(e['comp_size']-remaining)/1e6:.1f}/{e['comp_size']/1e6:.1f} MB", file=sys.stderr)
    payload = buf.getvalue()

    out = build_single_file_zip(e["name"], payload, e["method"], e["crc"], e["uncomp_size"])
    with open(args.out_zip, "wb") as f:
        f.write(out)

    # Sanity check: reopen what we just wrote.
    with zipfile.ZipFile(args.out_zip) as z:
        bad = z.testzip()
        info = z.infolist()[0]
    if bad is not None:
        raise SystemExit(f"produced ZIP is corrupt at {bad}")

    sha = hashlib.sha256(payload).hexdigest()
    print(f"wrote {args.out_zip} ({len(out)/1e6:.1f} MB)", file=sys.stderr)
    print(f"inner file : {info.filename}", file=sys.stderr)
    print(f"inner size : {info.file_size} bytes", file=sys.stderr)
    print(f"crc ok     : {info.CRC == e['crc']}", file=sys.stderr)
    print(f"sha256(apk): {sha}", file=sys.stderr)
    print(sha)  # stdout: machine-readable, for the workflow
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

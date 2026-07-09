#!/usr/bin/env python3
"""Generate the compact OUI vendor table `oui.bin` from Wireshark's `manuf`.

Usage:
    curl -s https://www.wireshark.org/download/automated/data/manuf -o manuf
    python3 generate-oui.py manuf oui.bin

The manuf format is tab-separated: `prefix<TAB>short<TAB>long`, where prefix
is `XX:XX:XX` (24-bit MA-L), `XX:XX:XX:XX:X0/28` (MA-M), or
`XX:XX:XX:XX:XX:X0/36` (MA-S).

Binary layout (all integers little-endian):

    magic "SPO1" (4 bytes)
    for each section in [24-bit, 28-bit, 36-bit]:
        count       u32
        keys        count * 6 bytes   -- masked prefix, big-endian, sorted asc
        nameOffsets count * u32        -- offset into this section's name blob
        blobLength  u32
        nameBlob    concatenated (u16 length + UTF-8 name) entries

Keys are fixed-width so the reader can binary-search them; a parallel offset
table makes name retrieval O(1). Lookups try 36-, then 28-, then 24-bit
prefixes (longest match wins).
"""
import struct
import sys


def parse(path):
    sections = {24: [], 28: [], 36: []}
    with open(path, "rb") as handle:
        for raw in handle:
            line = raw.decode("utf-8", "replace")
            if line.startswith("#") or not line.strip():
                continue
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 2:
                continue
            prefix = fields[0].strip()
            name = (fields[2] if len(fields) >= 3 and fields[2].strip() else fields[1]).strip()
            if not name:
                continue

            bits = 24
            if "/" in prefix:
                prefix, bits_text = prefix.split("/")
                bits = int(bits_text)
            hex_digits = prefix.replace(":", "").replace("-", "")
            if len(hex_digits) < 6:
                continue
            # Pad to 12 hex digits (48 bits), parse, keep the top `bits`.
            value = int(hex_digits.ljust(12, "0"), 16)
            mask = ((1 << bits) - 1) << (48 - bits)
            key = value & mask
            sections.setdefault(bits, []).append((key, name))
    return sections


def encode_section(records):
    # De-duplicate on key (keep first), then sort ascending for binary search.
    seen = {}
    for key, name in records:
        seen.setdefault(key, name)
    ordered = sorted(seen.items())

    keys = bytearray()
    offsets = bytearray()
    blob = bytearray()
    for key, name in ordered:
        keys += key.to_bytes(6, "big")
        offsets += struct.pack("<I", len(blob))
        encoded = name.encode("utf-8")[:255]
        blob += struct.pack("<H", len(encoded)) + encoded

    out = bytearray()
    out += struct.pack("<I", len(ordered))
    out += keys
    out += offsets
    out += struct.pack("<I", len(blob))
    out += blob
    return out


def main():
    source, dest = sys.argv[1], sys.argv[2]
    sections = parse(source)
    out = bytearray(b"SPO1")
    for bits in (24, 28, 36):
        out += encode_section(sections.get(bits, []))
    with open(dest, "wb") as handle:
        handle.write(out)
    counts = {b: len(sections.get(b, [])) for b in (24, 28, 36)}
    print(f"wrote {dest}: {len(out)} bytes, records {counts}")


if __name__ == "__main__":
    main()

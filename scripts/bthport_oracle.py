#!/usr/bin/env python3
"""Independent-oracle dump of Bluetooth pairings from a Windows ``SYSTEM`` hive.

Uses **regipy** — an independent, third-party REGF parser — to walk
``ControlSet00{1,2}\\Services\\BTHPORT\\Parameters\\{Devices,Keys}`` and emit one JSON record per
paired device. It shares **no code** with ``bluetooth-forensic``; the field selection (which subkey
is the device MAC, which value is ``Name`` / ``LastSeen`` / ``LastConnected``) follows RegRipper's
``bthport.pl`` (ADR-0003), but the hive parsing and value extraction are regipy's own.

This is the answer-key generator for the seam differential (``forensic/tests/hive_seam_oracle.rs``)
and the verification step for a minted real hive (``scripts/mint-bt-hive.md``). Run standalone:

    python3 scripts/bthport_oracle.py /path/to/SYSTEM

Exit codes: ``0`` success (JSON on stdout); ``3`` regipy unavailable (caller should SKIP); ``2``
usage; ``1`` parse error.
"""

import binascii
import json
import struct
import sys

CONTROL_SETS = ("ControlSet001", "ControlSet002")


def _mac(subkey_name):
    """A 12-hex subkey name -> ``AA:BB:CC:DD:EE:FF``; ``None`` if not a device MAC."""
    n = subkey_name
    if len(n) != 12:
        return None
    try:
        int(n, 16)
    except ValueError:
        return None
    up = n.upper()
    return ":".join(up[i : i + 2] for i in range(0, 12, 2))


def _binary_bytes(value):
    """regipy returns REG_BINARY as a hex string; recover the raw bytes."""
    if isinstance(value, str):
        try:
            return binascii.unhexlify(value)
        except (binascii.Error, ValueError):
            return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _decode_name(vtype, value):
    """Decode a ``Name`` value the way ``bthport.pl`` reads it (REG_SZ text or REG_BINARY ASCII)."""
    if value is None:
        return ""
    if vtype == "REG_SZ" or vtype == "REG_EXPAND_SZ":
        # regipy already decoded the UTF-16LE string (trailing NUL stripped).
        return value if isinstance(value, str) else ""
    raw = _binary_bytes(value)
    if raw is None:
        return ""
    if raw.endswith(b"\x00"):
        raw = raw[:-1]
    return raw.decode("utf-8", errors="replace")


def _decode_filetime(vtype, value):
    """First 8 bytes of a value as one little-endian ``u64``; ``None`` when absent/too short."""
    if value is None:
        return None
    raw = _binary_bytes(value)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack("<Q", raw[:8])[0]


def _values(subkey):
    out = {}
    try:
        for v in subkey.iter_values():
            out[v.name] = (str(v.value_type), v.value)
    except Exception:  # a valueless or malformed key contributes nothing
        pass
    return out


def dump(hive_path):
    from regipy.registry import RegistryHive
    from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException

    hive = RegistryHive(hive_path)
    devices = {}  # mac -> record (dedup across control sets; first wins)

    for cs in CONTROL_SETS:
        # link-key MACs for this control set (presence only; key bytes never read)
        link_key_macs = set()
        try:
            keys = hive.get_key("\\%s\\Services\\BTHPORT\\Parameters\\Keys" % cs)
            for adapter in keys.iter_subkeys() or []:
                for v in _values(adapter):
                    m = _mac(v)
                    if m:
                        link_key_macs.add(m)
        except (RegistryKeyNotFoundException, RegistryParsingException, Exception):
            pass

        try:
            dev_key = hive.get_key("\\%s\\Services\\BTHPORT\\Parameters\\Devices" % cs)
        except (RegistryKeyNotFoundException, RegistryParsingException, Exception):
            continue

        for sk in dev_key.iter_subkeys() or []:
            mac = _mac(sk.name)
            if mac is None:
                continue
            if mac in devices:
                continue
            vals = _values(sk)
            name_t, name_v = vals.get("Name", (None, None))
            ls_t, ls_v = vals.get("LastSeen", (None, None))
            lc_t, lc_v = vals.get("LastConnected", (None, None))
            devices[mac] = {
                "mac": mac,
                "name": _decode_name(name_t, name_v),
                "last_seen": _decode_filetime(ls_t, ls_v),
                "last_connected": _decode_filetime(lc_t, lc_v),
                "has_link_key": mac in link_key_macs,
            }

    return sorted(devices.values(), key=lambda d: d["mac"])


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: bthport_oracle.py <SYSTEM-hive>\n")
        return 2
    try:
        import regipy  # noqa: F401
    except ImportError:
        sys.stderr.write("regipy not installed (pip install regipy) — oracle unavailable\n")
        return 3
    try:
        records = dump(argv[1])
    except Exception as e:  # surface the offending hive + error, never a silent empty
        sys.stderr.write("oracle failed on %s: %r\n" % (argv[1], e))
        return 1
    json.dump(records, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

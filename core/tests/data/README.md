# bluetooth-core test data — provenance

The pure decoders (`bluetooth_core::parse_mac`, `decode_name`, `decode_filetime`, `decode_device`)
are validated by **synthetic `(name, bytes)` unit tests** (`core/src/tests.rs`) that reproduce the
exact on-disk shape of a real `BTHPORT` device record:

- the subkey **name** as 12 hex characters (device MAC, no separators);
- `Name` as UTF-16LE (`REG_SZ`, trailing NUL) and as an ASCII/UTF-8 `REG_BINARY` with a trailing
  NUL — both real-world encodings;
- `LastSeen` / `LastConnected` as an 8-byte little-endian `FILETIME`.

These are grounded in RegRipper's `bthport.pl` plugin (`keydet89/RegRipper3.0`): the subkey name is
the device unique ID (L66), `Name` is the friendly name (L72), and the two timestamps are read as
`unpack("VV", …)` — two little-endian `u32`s, i.e. one little-endian `u64` (L77/L82).

## FILETIME oracle (Tier-2)

`decode_filetime` is cross-checked against an **independent Python `datetime` oracle** in
`../../forensic/src/tests.rs` (`decode_filetime_matches_python_datetime_oracle`): several known
`FILETIME` values — including the Unix-epoch boundary `116444736000000000` — are decoded from their
little-endian bytes and rendered to UTC via `winreg-core`'s `filetime_to_datetime`, then compared to
the datetime Python computes with:

```python
from datetime import datetime, timezone, timedelta
datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
```

The values are second-aligned so the Python oracle and the jiff conversion agree to the exact second.

## Whole-hive walk fixture — SYNTHETIC (not committed; generated at test time)

The seam test (`../../forensic/tests/hive_seam.rs`) and its independent-oracle differential
(`../../forensic/tests/hive_seam_oracle.rs`) run over a **synthetic** REGF `SYSTEM` hive built
byte-by-byte at test time by `build_system_hive()` in `../../forensic/tests/common/mod.rs` — no image
file is committed. It is a minimal but valid REGF v1.5 hive (base block + one hbin of `nk`/`vk`/`li`
cells) with a full `ControlSet001\Services\BTHPORT\Parameters\{Devices,Keys}` subtree:

- device `AA:BB:CC:DD:EE:FF`, `Name` = `Sony WH-1000XM4` (REG_SZ/UTF-16LE), `LastSeen`
  `132317609750000000`, `LastConnected` `133200000000000000`, with a stored 16-byte classic link key
  under adapter `11:22:33:44:55:66`;
- device `00:1A:7D:DA:71:13`, `Name` = `Mouse` (REG_BINARY/ASCII), no timestamps, no link key;
- a `NotAMacSubkey` sibling that `parse_mac` must reject.

Generator: `../../forensic/tests/common/mod.rs::build_system_hive` (no external command; the builder is
the source of truth). Classification: **SYNTHETIC**.

### Independent oracle (Tier-2)

`../../scripts/bthport_oracle.py` re-parses the same bytes with **regipy** (a third-party REGF parser)
and emits the device set as JSON; `hive_seam_oracle.rs` reconciles it field-by-field with
`devices_from_hive`. Run `pip install regipy` to enable it; absent regipy the differential skips
cleanly. This lifts the seam over this scenario from tier-3 to tier-2.

## Tier-1 positive — a real minted hive (operator-supplied, pending)

No public `SYSTEM` hive containing Bluetooth pairings is available (the 2018 Digital Corpora *Lone
Wolf* SYSTEM hive has the BTHPORT stack + a host radio adapter but **zero** paired devices), and one
cannot be minted on a macOS host or a cloud VM (no Bluetooth radio). The real-hive tests
(`hive_seam_oracle.rs::real_hive_reconciles_with_regipy_oracle` and `system_real.rs`) are therefore
**env-gated on `BLUETOOTH_TEST_SYSTEM_HIVE`** and skip cleanly when the (non-committed) hive is absent.
To produce one, follow [`../../scripts/mint-bt-hive.md`](../../scripts/mint-bt-hive.md): pair a classic
Bluetooth device on a live Windows host, `reg save HKLM\SYSTEM`, then reconcile against the regipy
oracle and RegRipper's `bthport.pl` (`/tmp/RegRipper3.0`). When minted, add its provenance here
(source machine, Windows build, devices paired, sha256 — the hive stays gitignored/off-repo).

No test artifacts are committed to this directory.

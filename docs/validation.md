# Validation

`bluetooth-forensic` is validated in two honestly-separated layers. Read the tiers plainly:

## Decode primitives — Tier-2 (real-oracle-checked, not hand-graded)

The pure decoders (`bluetooth_core`) are exercised against sources independent of this code:

- **`decode_filetime`** is cross-checked against an **independent Python `datetime` oracle**
  (`decode_filetime_matches_python_datetime_oracle` in `forensic/src/tests.rs`). Several known
  `FILETIME` values — including the Unix-epoch boundary `116444736000000000` — are decoded from
  their little-endian bytes and rendered to UTC via `winreg-core`'s `filetime_to_datetime`, then
  compared to the datetime Python computes:

  ```python
  from datetime import datetime, timezone, timedelta
  datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
  ```

  | `FILETIME` (u64) | Python oracle | `bluetooth-forensic` |
  |---|---|---|
  | `116444736000000000` | `1970-01-01T00:00:00Z` | `1970-01-01T00:00:00Z` |
  | `132317609750000000` | `2020-04-19T09:09:35Z` | `2020-04-19T09:09:35Z` |
  | `130000000000000000` | `2012-12-14T23:06:40Z` | `2012-12-14T23:06:40Z` |

- **`parse_mac`** (12 hex → `AA:BB:CC:DD:EE:FF`) and **`decode_name`** (UTF-16LE `REG_SZ` /
  ASCII `REG_BINARY`, single trailing NUL stripped) are deterministic-by-construction and covered by
  synthetic unit tests.

Every offset is grounded in RegRipper's `bthport.pl` plugin (`keydet89/RegRipper3.0`): the subkey
name is the device unique ID (L66), `Name` is the friendly name (L72), and `LastSeen` /
`LastConnected` are read as `unpack("VV", …)` — two little-endian `u32`s, i.e. one little-endian
`u64` (L77/L82). `bluetooth_core::decode_filetime` reads exactly those 8 bytes as one LE `u64`.

## Whole-hive walk (`devices_from_hive`) — Tier-2 (independent-oracle-confirmed)

The seam that walks a `SYSTEM` hive's `BTHPORT` subtree and decodes every paired device is validated
at two levels:

- **Structure (Tier-3, always-run):** `forensic/tests/hive_seam.rs` drives `devices_from_hive` over a
  synthetic in-memory REGF hive built byte-by-byte (`forensic/tests/common/mod.rs`) with a full
  `ControlSet001\Services\BTHPORT\Parameters\{Devices,Keys}` subtree, asserting the two devices, their
  names, timestamps, and the link-key cross-reference. On its own this is tier-3 (self-authored
  fixture + self-authored answer).

- **Independent oracle (Tier-2, skip-when-absent):** `forensic/tests/hive_seam_oracle.rs` re-parses the
  **same bytes** with **regipy** — a third-party REGF parser sharing no code with this crate, driven by
  `scripts/bthport_oracle.py` — and reconciles the device set field-by-field (MAC, name, `LastSeen` /
  `LastConnected` FILETIMEs, link-key presence). Because the answer key now comes from an independent
  engine on the author's chosen scenario, the seam is tier-2, not tier-3. The oracle is skip-when-absent
  (no `python3`/`regipy` → the test prints `SKIP:` and passes), so the committed-bytes gate stays green
  off `hive_seam.rs`; installing `regipy` (`pip install regipy`) runs the differential.

  Building this fixture surfaced a real infidelity in the earlier synthetic hive: it appended the root
  `nk` as the *last* cell, whereas a real hive places the root as the *first* cell of the first hbin.
  Our `winreg-core` reader follows the base block's `root_key_offset` and was unaffected, but regipy
  locates the root by first-cell and read garbage — the differential caught it (RED), and the fixture
  now emits the root first (GREEN).

### Tier-1 positive — operator-supplied (pending)

The remaining gap is a **real** `SYSTEM` hive whose `BTHPORT\Parameters\Devices` actually contains
paired-device subkeys. No public `SYSTEM` hive with Bluetooth pairings is available (the 2018 Digital
Corpora *Lone Wolf* hive has the BTHPORT stack and a host radio adapter but **zero** paired devices),
and one cannot be minted on this host or a cloud VM (no Bluetooth radio). Both real-hive tests are
therefore **env-gated on `BLUETOOTH_TEST_SYSTEM_HIVE`** and skip cleanly when it is unset:

- `forensic/tests/hive_seam_oracle.rs::real_hive_reconciles_with_regipy_oracle` — reconciles the seam
  against the regipy oracle on the real hive (the seam-level tier-1 positive);
- `forensic/tests/system_real.rs` — drives the `bluetooth4n6` CLI and reconciles its device count
  against RegRipper's `bthport.pl` (the documented format authority, ADR-0003).

The exact mint-and-verify procedure is in
[`scripts/mint-bt-hive.md`](https://github.com/SecurityRonin/bluetooth-forensic/blob/main/scripts/mint-bt-hive.md);
provenance for a minted hive goes in
[`core/tests/data/README.md`](https://github.com/SecurityRonin/bluetooth-forensic/blob/main/core/tests/data/README.md).

## Value layout

Under `…\BTHPORT\Parameters\Devices\{deviceMAC}`:

- **Subkey name** — the device MAC as 12 hex characters (6 bytes, no separators), formatted
  `AA:BB:CC:DD:EE:FF`.
- **`Name`** — the friendly name; `REG_SZ` (UTF-16LE) or `REG_BINARY` (ASCII/UTF-8 with a trailing
  NUL). Both are decoded; a single trailing NUL is stripped; odd lengths never panic.
- **`LastSeen` / `LastConnected`** — an 8-byte little-endian `FILETIME` each; a value shorter than 8
  bytes decodes to `None`.

A stored plaintext classic link key under `…\Parameters\Keys\{adapterMAC}\{deviceMAC}` is recorded
by **presence and length only** — the key bytes are never read or emitted.

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

## Whole-hive walk — validation-pending a real hive

No public `SYSTEM` hive containing Bluetooth pairings is available, and none can be minted in this
environment. The end-to-end test (`forensic/tests/system_real.rs`) that drives the real
`bluetooth4n6` binary over a hive via `winreg-core` and reconciles its paired-device count against
RegRipper's `bthport.pl` oracle is therefore **env-gated on `BLUETOOTH_TEST_SYSTEM_HIVE`** and
**skips cleanly** when the (non-committed) hive is absent — which is the case today.

This layer is **not yet Tier-1**. A qualifying hive is mintable by pairing a device on a live Windows
Bluetooth host and exporting the `SYSTEM` hive, then reconciling `bluetooth4n6` against `bthport.pl`.
Provenance and the exact procedure are in
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

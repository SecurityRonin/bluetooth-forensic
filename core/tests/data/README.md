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

## Whole-hive walk — validation-pending a real hive

No public `SYSTEM` hive containing Bluetooth pairings is available, and none can be minted in this
environment. The end-to-end test (`../../forensic/tests/system_real.rs`) is therefore **env-gated on
`BLUETOOTH_TEST_SYSTEM_HIVE`** and skips cleanly when the (non-committed) hive is absent. To run it,
point the var at a real `SYSTEM` hive; the test reconciles `bluetooth4n6`'s paired-device count
against RegRipper's `bthport.pl` oracle (`/tmp/RegRipper3.0`). Such a hive is mintable by pairing a
device on a live Windows Bluetooth host and exporting the `SYSTEM` hive.

No test artifacts are committed to this directory.

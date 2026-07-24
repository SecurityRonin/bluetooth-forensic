# 3. RegRipper `bthport.pl` as the format authority — MAC, Name, and little-endian FILETIME layout

Date: 2026-07-24
Status: Accepted

## Context

There is no published Microsoft specification for the `BTHPORT` pairing-record
layout, so the byte-level decode decisions (where the device MAC lives, how the
friendly `Name` is encoded, the width and endianness of the timestamps) need an
authoritative reference rather than guesswork. The fleet's Research-First
discipline requires grounding a format decoder in the reverse-engineered reference
the community has settled on before writing the parser.

RegRipper's `bthport.pl` plugin (`keydet89/RegRipper3.0`) is that reference for
Bluetooth pairing artifacts and is the tool the end-to-end walk reconciles against
(`forensic/tests/system_real.rs`).

## Decision

Ground every byte-handling choice in `bthport.pl`, cited line-by-line in the code
(`core/src/lib.rs` and `forensic/src/bin/bluetooth4n6.rs` doc comments):

- **Device MAC = the subkey name** under `…\BTHPORT\Parameters\Devices\{deviceMAC}`
  — 12 hex characters (6 bytes, no separators) → `AA:BB:CC:DD:EE:FF`
  (`bthport.pl` L66, `get_name`; `parse_mac`).
- **Friendly name = the `Name` value** — decoded as `REG_SZ` UTF-16LE **or**
  `REG_BINARY` ASCII with a trailing NUL, both handled (L72; `decode_name(bytes,
  is_reg_sz)`).
- **`LastSeen` / `LastConnected` = 8-byte little-endian `FILETIME`** — RegRipper
  reads them as `unpack("VV", …)`, two little-endian `u32`s, i.e. one little-endian
  `u64` (L77/L82; `decode_filetime`).
- **Control-set coverage** — the CLI walks `ControlSet001`/`002`, following the
  device subkeys under `services\BTHPORT\Parameters\Devices` (L56).

## Consequences

- The endianness and offsets are traceable to a named, community-vetted reference,
  not to the model's recollection of a format.
- `decode_name` handles both real-world encodings of `Name` rather than assuming
  one, matching what `bthport.pl` observes in the wild.
- Correctness of `decode_filetime` is cross-checked against an independent Python
  `datetime` oracle (Tier-2; `test(forensic): RED` commit 90fee82); the whole-hive
  walk reconciles device counts against `bthport.pl` when pointed at a real hive.

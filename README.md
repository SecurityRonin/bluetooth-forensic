# bluetooth-forensic

[![CI](https://github.com/SecurityRonin/bluetooth-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/bluetooth-forensic/actions)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Prove which Bluetooth devices a Windows box paired with — MAC, name, and last-seen/last-connected time — straight from the `SYSTEM` hive, on any OS.** A panic-free-by-construction reader for the MS Bluetooth stack's `BTHPORT` pairing records, plus an analyzer that surfaces a stored, extractable classic link key.

## Run it

```console
$ cargo install bluetooth-forensic          # installs the bluetooth4n6 binary
$ bluetooth4n6 /path/to/SYSTEM
Bluetooth: 2 paired device(s), 1 with a stored link key
  A0:E6:F8:11:22:33  "Jabra Elite 75t"
    LastSeen: 2020-04-19T09:09:35Z   LastConnected: 2020-04-19T18:41:07Z   link-key: present (16 bytes)
  00:16:94:8D:12:34  "Logitech K380"
    LastSeen: 2020-03-02T08:15:00Z   LastConnected: -   link-key: none

Findings (3, 1 graded):
  [INFO] BLUETOOTH-PAIRED-DEVICE
    Paired Bluetooth device A0:E6:F8:11:22:33 (Jabra Elite 75t). LastSeen 2020-04-19T09:09:35Z, LastConnected 2020-04-19T18:41:07Z. A plaintext classic link key is stored for this device. LastConnected/LastSeen may reflect pairing time, not last use — corroborate.
  [LOW] BLUETOOTH-LINK-KEY-STORED
    A plaintext classic Bluetooth link key for device A0:E6:F8:11:22:33 (Jabra Elite 75t) is stored in the SYSTEM hive and is extractable — consistent with credential material that enables impersonation of the pairing.
```

*(Illustrative output — the walk is validation-pending a real hive; see [Validation](#validation).)*

## What it decodes

The MS Bluetooth stack (`SYSTEM\ControlSet00N\Services\BTHPORT\Parameters`) records every paired device:

- Under `Devices\{deviceMAC}`, the subkey **name** is the device MAC as 12 hex characters (6 bytes, no separators) → `AA:BB:CC:DD:EE:FF`. The `Name` value is the friendly name (`REG_SZ` UTF-16LE **or** `REG_BINARY` ASCII with a trailing NUL — both handled). `LastSeen` and `LastConnected` are each an **8-byte little-endian `FILETIME`**. `bluetooth4n6` walks `ControlSet001`/`002`.
- Under `Keys\{adapterMAC}\{deviceMAC}`, a **plaintext 16-byte classic link key** is stored per device. `bluetooth4n6` records only its **presence and length** — it never reads or emits the key bytes.

> Bluetooth pairing records establish that a device was **paired** with this machine. The timestamps may reflect *pairing* time, not last use — corroborate. Findings are observations, never verdicts.

## Layers

- **`bluetooth-core`** — pure decoders with no hive I/O: `parse_mac`, `decode_name(bytes, is_reg_sz)`, `decode_filetime`, and `decode_device` → `BluetoothDevice`. `#![forbid(unsafe_code)]`, panic-free by lint.
- **`bluetooth-forensic`** — `audit(&[BluetoothDevice]) -> Vec<BluetoothFinding>` (graded `forensicnomicon` findings) and the `bluetooth4n6` CLI, which does the `winreg-core` hive walking.

## Validation

Byte handling is grounded in RegRipper's **`bthport.pl`** plugin (`keydet89/RegRipper3.0`): the subkey name is the device unique ID (L66), `Name` is the friendly name (L72), and `LastSeen`/`LastConnected` are `unpack("VV", …)` — two little-endian `u32`s, i.e. one LE `u64` (L77/L82).

- **Decode primitives — Tier-2.** `decode_filetime` is cross-checked against an independent **Python `datetime` oracle** (epoch boundary + real values); `parse_mac`/`decode_name` are deterministic-by-construction.
- **Whole-hive walk — validation-pending a real hive.** No public `SYSTEM` hive with Bluetooth pairings exists to mint here, so the end-to-end test (`forensic/tests/system_real.rs`) is env-gated on `BLUETOOTH_TEST_SYSTEM_HIVE` and skips cleanly until pointed at a real hive, where it reconciles the device count against `bthport.pl`.

See [Validation](https://securityronin.github.io/bluetooth-forensic/validation/) for the full tiering.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `BLUETOOTH-PAIRED-DEVICE` | Info | — | Every paired device (evidence: MAC, name, LastSeen/LastConnected, with the pairing-time caveat). |
| `BLUETOOTH-LINK-KEY-STORED` | Low | T1552.002 | A plaintext classic link key is stored for the device (extractable; enables impersonation). |

---

[Privacy Policy](https://securityronin.github.io/bluetooth-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/bluetooth-forensic/terms/) · © 2026 Security Ronin Ltd

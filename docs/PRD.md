# bluetooth-forensic — Product Requirements

*A reverse-written intent document. Every current-state claim is grounded in a
same-session read of `core/`, `forensic/`, and the repo manifests (2026-07-24). The
load-bearing decisions live as ADRs [0001](decisions/0001-reader-analyzer-split.md)–[0008](decisions/0008-msrv-floor-1.85-with-1.96-dev-toolchain.md)
under [`docs/decisions/`](decisions/).*

## Executive Summary

`bluetooth4n6` proves which Bluetooth devices a Windows machine paired with —
MAC, friendly name, and last-seen/last-connected time — straight from the `SYSTEM`
registry hive, on any operating system. It reads the MS Bluetooth stack's
`BTHPORT` pairing records with the fleet's `winreg-core` hive parser, decodes each
device, and emits `forensicnomicon` findings: one neutral evidence record per
paired device, plus a graded signal when a plaintext classic link key is stored
(extractable credential material). The tool records only the **presence and
length** of that key — never its bytes (ADR 0006).

The repo is a two-crate workspace (ADR 0001): a pure, `unsafe`-forbidden,
panic-free decoder library (`bluetooth-forensic-core`) and an analyzer +
`bluetooth4n6` CLI (`bluetooth-forensic`). It is a single static binary an
examiner installs with `cargo install` and runs against a hive path.

## 1. Problem

An investigator often needs to establish that a specific peripheral — a headset, a
keyboard, a phone, a rogue HID device — was paired with a Windows host, and
roughly when. That evidence sits in the `SYSTEM` hive under
`…\BTHPORT\Parameters`, but reading it by hand means knowing the exact subkey
layout, that the MAC is the subkey name as raw hex, that `Name` may be `REG_SZ`
UTF-16 or `REG_BINARY` ASCII, and that the timestamps are little-endian
`FILETIME`s. RegRipper's `bthport.pl` plugin encodes that knowledge but runs on
Perl against a mounted hive. A native, cross-platform tool that goes from a hive
file to graded findings in one command — and that treats the stored link key as
the credential it is — did not exist in the fleet.

## 2. Users and use case

- **DFIR analysts / examiners** answering "did device X pair with this host, and
  when?" from an acquired `SYSTEM` hive, on macOS/Linux/Windows workstations.
- **Fleet orchestration** (Issen): the `bluetooth-forensic` analyzer's
  `forensicnomicon` findings aggregate into a unified `Report` alongside every
  other artifact analyzer.
- **Rust developers** who want just the decoders: `bluetooth-forensic-core` is an
  independently consumable, low-MSRV (ADR 0008), `Path`-free byte decoder.

## 3. What it does

1. **Walk the hive.** `bluetooth4n6 /path/to/SYSTEM` opens the hive with
   `winreg-core` and walks `Services\BTHPORT\Parameters\Devices\{deviceMAC}` across
   `ControlSet001`/`002` (ADR 0004).
2. **Decode each device** (`bluetooth_core`, grounded in `bthport.pl` — ADR 0003):
   - device MAC from the subkey name (12 hex → `AA:BB:CC:DD:EE:FF`);
   - friendly `Name` (`REG_SZ` UTF-16LE or `REG_BINARY` ASCII, both handled);
   - `LastSeen` / `LastConnected` from 8-byte little-endian `FILETIME`s, rendered
     to UTC.
3. **Check for a stored link key** under `…\Parameters\Keys\{adapterMAC}\{deviceMAC}`
   and record its presence + length only (ADR 0006).
4. **Grade and report** (`bluetooth_forensic::audit` — ADR 0007): an `Info`
   `BLUETOOTH-PAIRED-DEVICE` per device (with the pairing-time caveat) and a `Low`
   `BLUETOOTH-LINK-KEY-STORED` (MITRE `T1552.002`) when a plaintext key is stored.

## 4. Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `BLUETOOTH-PAIRED-DEVICE` | Info | — | Every paired device (evidence: MAC, name, LastSeen/LastConnected, with the pairing-time caveat). |
| `BLUETOOTH-LINK-KEY-STORED` | Low | T1552.002 | A plaintext classic link key is stored for the device (extractable; enables impersonation). |

No High-severity findings: the hive establishes that a device was *paired*, not
what was done with it (ADR 0007).

## 5. Artifact family

- **Source:** the Windows `SYSTEM` hive, `…\BTHPORT\Parameters\{Devices,Keys}`.
- **Records:** per-device MAC, friendly name, `LastSeen`/`LastConnected`
  `FILETIME`s, and stored classic link-key presence.
- **Reference authority:** RegRipper `bthport.pl` (`keydet89/RegRipper3.0`),
  cited line-by-line in the decoder source (ADR 0003).

## 6. Scope

- Read the `BTHPORT` pairing records from a `SYSTEM` hive on any host OS.
- Decode device identity, friendly name, and pairing/connection timestamps.
- Report a stored classic link key's presence and length as a graded finding.
- Ship as one `cargo install`-able static binary plus a reusable decoder library.

## 7. Non-goals

- **Emitting link-key bytes.** Never, in any mode — presence and length only
  (ADR 0006). Key extraction is a separate, deliberately-scoped concern.
- **Hive I/O in the core crate.** The decoders stay byte-in, record-out; hive
  reading lives in the CLI via `winreg-core` (ADR 0004).
- **BLE / live-radio capture.** This is a stored-artifact analyzer over the
  Windows registry, not a Bluetooth radio or `btleplug`-style live tool.
- **Asserting device *use* or legal conclusions.** Findings are observations; the
  timestamps may reflect pairing time, and the tool says so (ADR 0007).
- **Non-Windows Bluetooth stores.** Only the MS Bluetooth stack's `BTHPORT`
  layout is in scope today.

## 8. Validation approach

Grounded in RegRipper `bthport.pl` (ADR 0003) and tiered honestly (README →
Validation; `securityronin.github.io/bluetooth-forensic/validation/`):

- **Decode primitives — Tier-2.** `decode_filetime` is cross-checked against an
  independent Python `datetime` oracle (epoch boundary + real values; RED commit
  90fee82); `parse_mac` / `decode_name` are deterministic-by-construction.
- **Whole-hive walk — validation-pending a real hive.** No public `SYSTEM` hive
  carrying Bluetooth pairings exists to mint here, so the end-to-end test
  (`forensic/tests/system_real.rs`) is env-gated on `BLUETOOTH_TEST_SYSTEM_HIVE`
  and skips cleanly until pointed at a real hive, where it reconciles the device
  count against `bthport.pl` (the independent reference tool).
- **Robustness — fuzzed.** `fuzz_parse` and `fuzz_forensic` (`fuzz/fuzz_targets/`)
  drive the decoders and the decode→audit pipeline under `cargo-fuzz`, smoke-run in
  CI, with the no-panic invariant (ADR 0005).

## 9. Current state and open items

- The decoders, analyzer, and `bluetooth4n6` CLI are implemented and tested
  (commits a8e6f11 → b2c5d94); pre-publish infra (publishable core name, MSRV job,
  cargo-vet, fuzz targets, docs) is in place (commits dcadbf1, 5ffc412, df1cd0d).
- **Real-hive validation is the primary open item** — the end-to-end walk needs a
  real `SYSTEM` hive with Bluetooth pairings to move from "validation-pending" to a
  reconciled Tier-1/Tier-2 result; the README's illustrative output is labelled as
  such until then.
- **MSRV floor rationale** (ADR 0008): the specific constraint fixing the floor at
  1.85 is not recovered; record the constraining dependency if it is later
  identified.

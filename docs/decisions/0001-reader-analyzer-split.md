# 1. Reader/analyzer split — `core/` decoder, `forensic/` analyzer + CLI

Date: 2026-07-24
Status: Accepted

## Context

This repo turns Windows Bluetooth pairing evidence (the MS Bluetooth stack's
`BTHPORT` records in the `SYSTEM` hive) into forensic findings. Two distinct
concerns live in that job: (a) turning raw subkey names and value bytes into
typed device records, and (b) grading those records into `forensicnomicon`
findings and presenting them to an examiner.

The fleet crate-structure standard (`ronin-issen/CLAUDE.md` → "Crate-structure
standard — reader/analyzer split") makes this a binding shape for every format:
one workspace repo named `<x>-forensic` with a `core/` reader crate (no findings)
and a `forensic/` analyzer crate (the anomaly auditor). A downstream Rust tool
that only needs the decoders should not have to compile the analyzer, the CLI, or
`winreg-core`.

## Decision

Split the workspace into two members (`Cargo.toml` `members = ["core",
"forensic"]`):

- **`core/` → `bluetooth-forensic-core`** (imports as `bluetooth_core`): pure
  decoder primitives with no hive I/O — `parse_mac`, `decode_name`,
  `decode_filetime`, `decode_device` → `BluetoothDevice` (`core/src/lib.rs`). No
  findings, no registry access.
- **`forensic/` → `bluetooth-forensic`**: `audit(&[BluetoothDevice]) ->
  Vec<BluetoothFinding>` emitting graded `forensicnomicon` findings, plus the
  `bluetooth4n6` binary (`forensic/src/bin/bluetooth4n6.rs`).

The two crates are versioned independently (`Cargo.toml` comment: "`version` is
NOT hoisted — core and forensic are versioned independently"). The TDD history
kept the split from the first commit — `test(core): RED` (a8e6f11) / `feat(core):
GREEN` (4ac1d13) built the decoders before `feat(forensic): GREEN — Bluetooth
analyzer + bluetooth4n6 CLI` (b2c5d94).

## Consequences

- A third-party consumer depends on `bluetooth-forensic-core` alone for the
  decoders, without pulling the analyzer or `winreg-core`.
- The two crates publish and version on their own cadence.
- The layering must stay acyclic: `forensic` depends on `core`, never the reverse.
- Where the analyzer needs structure the reader's happy-path API would hide, it is
  free to drop lower (see ADR 0004) — the split does not force every audit through
  the reader.

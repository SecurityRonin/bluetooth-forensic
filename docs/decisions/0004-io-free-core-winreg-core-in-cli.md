# 4. I/O-free decoder core; the CLI walks the `SYSTEM` hive with `winreg-core`

Date: 2026-07-24
Status: Accepted

## Context

Decoding a Bluetooth pairing record needs two things: reading values out of a REGF
`SYSTEM` hive, and interpreting the bytes of each value. These are separable, and
the fleet keeps PARSER-layer code medium-agnostic — a parser accepts `Path` or
`&[u8]` and never imports a container/hive layer, so it can run over a live file,
an extracted artifact, or bytes carved from memory (`ronin-issen/CLAUDE.md` →
dependency rules; VFS/dependency-preference).

The fleet already publishes a REGF hive parser, `winreg-core`, and the
"prefer our own crates" rule makes it the hive reader rather than a hand-rolled
walk or a third-party registry crate.

## Decision

Keep the decoder core **hive-I/O-free**: `bluetooth-forensic-core` takes a subkey
name and raw value bytes and never touches the registry (`core/src/lib.rs`:
"never touches the registry"). The `bluetooth4n6` binary is the only place hive
I/O happens — it opens the `SYSTEM` hive with **`winreg-core`**, walks
`Services\BTHPORT\Parameters\Devices\{MAC}` across control sets, reads each
device's `Name` / `LastSeen` / `LastConnected` values and checks the
`…\Parameters\Keys` subtree, then feeds the bytes to
`bluetooth_core::decode_device` and `bluetooth_forensic::audit`
(`forensic/src/bin/bluetooth4n6.rs`; `Cargo.toml` `winreg-core = "0.2"`).

## Consequences

- The decoders are reusable over any byte source — a live hive, an image-extracted
  hive, or a carved fragment — with no dependency on `winreg-core`.
- Hive-format concerns (REGF structure, control-set selection) live in one place,
  `winreg-core`, and benefit every fleet consumer of it, not just this repo.
- The `bluetooth4n6` binary is a thin wiring layer (Humble Object): the decisions
  live in the two libraries; the binary only opens, walks, and renders.
- `winreg-core` is pinned by caret at `0.2`; a published fleet release is preferred
  over a path dependency per the fleet dependency-freshness policy.

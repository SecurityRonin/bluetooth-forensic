# 5. Panic-free, `unsafe`-forbidden, fuzzed parsing of untrusted hive bytes

Date: 2026-07-24
Status: Accepted

## Context

Every byte this tool parses comes from a `SYSTEM` hive, which is
attacker-controllable evidence. A lying length, a truncated `Name` value, or an
odd-length timestamp buffer must never crash the tool or produce silently wrong
output — a forensic tool that panics on a crafted artifact is a denial-of-service
on the investigation. The fleet's Paranoid Gatekeeper standard
(`ronin-issen/CLAUDE.md`) makes a panic-free posture mandatory for every
`*-core`/`*-forensic` crate.

Unlike the fleet's mmap-based container readers, these decoders do no memory
mapping and no FFI — there is no benefit that would justify any `unsafe`, so the
crate can hold the stronger `forbid` posture rather than `deny` + a bounded allow.

## Decision

Enforce panic-freedom statically and dynamically:

- **Static.** The workspace sets `unsafe_code = "forbid"` and denies
  `clippy::unwrap_used` / `expect_used` in production code (`Cargo.toml`
  `[workspace.lints]`); each crate carries `#![forbid(unsafe_code)]`
  (`core/src/lib.rs`, `forensic/src/lib.rs`, the CLI). Every multi-byte read is
  bounds-checked and an odd length yields a shorter decode, never a panic
  (`core/src/lib.rs`: "panic-free: every multi-byte read is bounds-checked and odd
  lengths yield a shorter decode").
- **Dynamic.** Two `cargo-fuzz` targets exercise the surface — `fuzz_parse`
  (decoder primitives) and `fuzz_forensic` (the decode → audit pipeline)
  (`fuzz/fuzz_targets/`) — built and smoke-run by `.github/workflows/fuzz.yml`,
  with the invariant that no input may panic.

The README badges the earned half of this: `unsafe forbidden`.

## Consequences

- Malformed hive bytes degrade to a shorter decode or an error, never a crash.
- The `forbid` (not `deny`) posture is provable and badge-able — `rg
  'unsafe'` is expected to find only the lint declarations, no `unsafe` blocks.
- The static lints occasionally require more verbose bounds-checked code than a
  quick `unwrap`; the fuzz targets are maintained surface that runs in CI.

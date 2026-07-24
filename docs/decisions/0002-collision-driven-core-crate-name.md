# 2. Collision-driven crate name — publish `bluetooth-forensic-core`, keep the `bluetooth_core` import path

Date: 2026-07-24
Status: Accepted

## Context

The reader/analyzer split (ADR 0001) wants the reader crate to import as
`bluetooth_core`. But crates.io treats `-` and `_` as one name, and the name
`bluetooth_core` is already claimed by an unrelated third party — a BLE/`btleplug`
wrapper — so the reader cannot publish under the bare name (`core/Cargo.toml`
comment; `Cargo.toml` `[workspace.dependencies]` comment).

The fleet naming grammar (`ronin-issen/CLAUDE.md` → "Crate naming grammar")
covers exactly this case: when `<x>-core` is taken on crates.io by an unrelated
third party, the reader takes the `<x>-forensic-core` form (self-describing on
crates.io as "the core of the `<x>-forensic` suite"), while `[lib] name` keeps the
short import path so consumers are unaffected. The reference is `zfs-forensic-core`.

## Decision

Publish the reader as **`bluetooth-forensic-core`** with **`[lib] name =
"bluetooth_core"`** (`core/Cargo.toml`). The workspace declares the dependency
with an alias so the analyzer's source is unchanged:

```toml
bluetooth-core = { path = "core", version = "0.1.0", package = "bluetooth-forensic-core" }
```

(`Cargo.toml` `[workspace.dependencies]`). Consumers still write `use
bluetooth_core::…`; the crates.io package name carries the suite prefix. This was
finalized in the pre-publish gate pass (commit df1cd0d, "publishable core crate
name (bluetooth-forensic-core)").

## Consequences

- The reader is publishable to crates.io without colliding with the existing
  `bluetooth_core` package.
- The import path stays `bluetooth_core`, so ADR 0001's decoder API reads
  unchanged in the analyzer and the CLI.
- The name is self-describing bare: `bluetooth-forensic-core` reads as the core of
  the `bluetooth-forensic` suite in search and `cargo add`, with no GitHub context.

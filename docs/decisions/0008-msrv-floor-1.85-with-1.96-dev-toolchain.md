# 8. Declared MSRV floor 1.85, developed on the 1.96 stable toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` → "Rust MSRV & Toolchain") keeps
two versions separate: the **dev toolchain** (the current stable, pinned fleet-wide
in `rust-toolchain.toml`) and the **declared MSRV** (`rust-version`, a
downstream-facing promise). Published libraries keep a low, CI-verified MSRV so
they stay broadly consumable; `bluetooth-forensic-core` is exactly such a
published library (ADR 0002).

## Decision

- **Develop on the pinned stable**, `1.96.0` (`rust-toolchain.toml`, with `clippy`
  and `rustfmt` components declared in the toml as the single source of truth).
- **Declare `rust-version = "1.85"`** workspace-wide (`Cargo.toml`
  `[workspace.package]`), and **verify it in CI** with a dedicated MSRV job that
  pins `dtolnay/rust-toolchain` to `1.85` so the job genuinely runs on the declared
  floor (`.github/workflows/ci.yml` → `msrv:` "MSRV (1.85)"). The floor was wired
  in the pre-publish gate pass (commit df1cd0d).

## Consequences

- `bluetooth-forensic-core` is consumable by any toolchain ≥ 1.85, and the promise
  is a real, CI-checked guarantee rather than an aspiration.
- Raising the floor later narrows the crate's audience, so it is treated as a
  near-breaking change requiring an explicit reason.
- **Unrecovered rationale:** why the floor is **1.85** specifically — rather than
  the fleet's usual `1.75`/`1.80` library floor — is not recovered from available
  history. The most likely cause is a minimum imposed by a dependency
  (`forensicnomicon` / `winreg-core`) or an edition/feature requirement, but no
  commit or comment states it. Rationale reconstructed from structure; original
  intent not recovered in available history. If the constraining dependency is
  later identified, record it here.

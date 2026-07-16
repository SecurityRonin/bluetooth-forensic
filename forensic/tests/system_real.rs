//! End-to-end validation of the `bluetooth4n6` binary against a **real** `SYSTEM` hive that
//! contains Bluetooth pairings — exercises the `winreg-core` control-set / `BTHPORT` navigation and
//! per-value decode that the pure library does not cover.
//!
//! **Validation-pending a real hive.** No public `SYSTEM` hive with Bluetooth pairings is available
//! and none can be minted in this environment, so this test is **env-gated on
//! `BLUETOOTH_TEST_SYSTEM_HIVE`** and **skips cleanly** (prints `SKIP:` and passes) when the var is
//! unset — which is the case today. To run it, point the var at a real `SYSTEM` hive; the test
//! reconciles the paired-device count `bluetooth4n6` reports against RegRipper's `bthport.pl`
//! oracle (`/tmp/RegRipper3.0`, overridable via `BLUETOOTH_TEST_REGRIPPER`). A hive is mintable by
//! pairing a device on a live Windows Bluetooth host and exporting `SYSTEM`. See
//! `../core/tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

/// Count device blocks in `bluetooth4n6` output from its summary line
/// (`Bluetooth: N paired device(s), …`).
fn parse_our_count(stdout: &str) -> Option<usize> {
    let line = stdout.lines().find(|l| l.starts_with("Bluetooth:"))?;
    let n = line.strip_prefix("Bluetooth:")?.split_whitespace().next()?;
    n.parse().ok()
}

/// Count `Device Unique ID:` lines in bthport.pl output (one per paired device — L65 of the plugin).
fn parse_oracle_count(stdout: &str) -> usize {
    stdout
        .lines()
        .filter(|l| l.contains("Device Unique ID:"))
        .count()
}

#[test]
fn bluetooth4n6_reconciles_with_bthport_oracle_on_a_real_system_hive() {
    let Ok(hive) = std::env::var("BLUETOOTH_TEST_SYSTEM_HIVE") else {
        eprintln!(
            "SKIP: set BLUETOOTH_TEST_SYSTEM_HIVE to a real SYSTEM hive with Bluetooth pairings \
             (validation-pending a real hive)"
        );
        return;
    };

    let out = Command::new(env!("CARGO_BIN_EXE_bluetooth4n6"))
        .arg(&hive)
        .output()
        .expect("run bluetooth4n6");
    assert!(
        out.status.success(),
        "bluetooth4n6 failed: {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let our_count = parse_our_count(&stdout).expect("summary line with a device count");

    // Cross-check against the bthport.pl oracle when RegRipper is available.
    let rr =
        std::env::var("BLUETOOTH_TEST_REGRIPPER").unwrap_or_else(|_| "/tmp/RegRipper3.0".into());
    let rip = Path::new(&rr).join("rip.pl");
    if rip.exists() {
        let oracle = Command::new("perl")
            .arg(&rip)
            .args(["-r", &hive, "-p", "bthport"])
            .output()
            .expect("run bthport.pl");
        let oracle_out = String::from_utf8_lossy(&oracle.stdout);
        let oracle_count = parse_oracle_count(&oracle_out);
        assert_eq!(
            our_count, oracle_count,
            "device count disagrees with bthport.pl (ours {our_count}, oracle {oracle_count})"
        );
    } else {
        eprintln!("NOTE: {rr}/rip.pl not found — checked count > 0 only, not reconciled vs oracle");
        assert!(our_count > 0, "expected at least one paired device");
    }
}

//! **Independent-oracle differential** for the [`bluetooth_forensic::devices_from_hive`] seam.
//!
//! The tier-3 gap this closes: `hive_seam.rs` proves the seam decodes a hive *we* built to an answer
//! *we* wrote — the seam agreeing with itself. Here the **same bytes** are re-parsed by an
//! independent third-party REGF parser (**regipy**, driven by `scripts/bthport_oracle.py`), and the
//! two device sets are reconciled field-by-field (MAC, friendly name, `LastSeen` / `LastConnected`
//! FILETIMEs, stored-link-key presence). Because the answer key now comes from an independent
//! engine, the seam over this scenario is **tier-2**, not tier-3.
//!
//! Two hives are reconciled:
//! - the **synthetic** fixture from [`common::build_system_hive`] — always, giving a self-contained
//!   tier-2 check whenever the oracle is installed;
//! - a **real** `SYSTEM` hive when `BLUETOOTH_TEST_SYSTEM_HIVE` points at one — the genuine tier-1
//!   positive (operator-supplied; see `scripts/mint-bt-hive.md`).
//!
//! The oracle is a *skip-when-absent* dependency, per the fleet gate discipline: with no `python3`
//! or no `regipy` the test prints `SKIP:` and passes, so the committed-bytes CI gate stays green off
//! `hive_seam.rs` alone. Install the oracle (`pip install regipy`) to actually run the differential.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::process::Command;

use bluetooth_forensic::{devices_from_hive, BluetoothDevice};
use common::build_system_hive;
use winreg_core::hive::Hive;

/// A device normalized for cross-implementation comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Rec {
    mac: String,
    name: String,
    last_seen: Option<u64>,
    last_connected: Option<u64>,
    has_link_key: bool,
}

/// Our seam's view, sorted by MAC.
fn ours(devices: &[BluetoothDevice]) -> Vec<Rec> {
    let mut v: Vec<Rec> = devices
        .iter()
        .map(|d| Rec {
            mac: d.mac.clone(),
            name: d.name.clone(),
            last_seen: d.last_seen_filetime,
            last_connected: d.last_connected_filetime,
            has_link_key: d.has_link_key,
        })
        .collect();
    v.sort();
    v
}

/// The independent oracle's view of the same hive file, or `None` when the oracle is unavailable
/// (no `python3` / no `regipy`) — signalling the caller to SKIP. A genuine parse failure panics
/// (loud), never a silent empty.
fn oracle(hive_path: &Path) -> Option<Vec<Rec>> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/bthport_oracle.py");
    let out = match Command::new("python3").arg(script).arg(hive_path).output() {
        Ok(o) => o,
        Err(_) => return None, // no python3 interpreter → skip
    };
    if out.status.code() == Some(3) {
        return None; // regipy not installed → skip
    }
    assert!(
        out.status.success(),
        "oracle failed on {}: {}",
        hive_path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("oracle emits valid JSON");
    let mut recs: Vec<Rec> = json
        .as_array()
        .expect("oracle emits a JSON array")
        .iter()
        .map(|d| Rec {
            mac: d["mac"].as_str().unwrap().to_string(),
            name: d["name"].as_str().unwrap().to_string(),
            last_seen: d["last_seen"].as_u64(),
            last_connected: d["last_connected"].as_u64(),
            has_link_key: d["has_link_key"].as_bool().unwrap(),
        })
        .collect();
    recs.sort();
    Some(recs)
}

#[test]
fn synthetic_hive_reconciles_with_regipy_oracle() {
    let image = build_system_hive();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("bt-synth-SYSTEM-{}", std::process::id()));
    std::fs::write(&path, &image).unwrap();

    let ours = ours(&devices_from_hive(
        &Hive::from_bytes(image).expect("valid fixture hive"),
    ));

    let Some(oracle) = oracle(&path) else {
        eprintln!("SKIP: regipy oracle unavailable (pip install regipy) — synthetic differential");
        let _ = std::fs::remove_file(&path);
        return;
    };
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        ours, oracle,
        "devices_from_hive disagrees with the independent regipy oracle on the synthetic hive"
    );
    // Guard against a vacuous pass: the fixture has two devices, so the oracle must have found them.
    assert_eq!(
        oracle.len(),
        2,
        "oracle found {} devices, expected 2",
        oracle.len()
    );
}

#[test]
fn real_hive_reconciles_with_regipy_oracle() {
    let Ok(hive_path) = std::env::var("BLUETOOTH_TEST_SYSTEM_HIVE") else {
        eprintln!(
            "SKIP: set BLUETOOTH_TEST_SYSTEM_HIVE to a real SYSTEM hive with Bluetooth pairings \
             (tier-1 positive — operator-supplied; see scripts/mint-bt-hive.md)"
        );
        return;
    };
    let path = Path::new(&hive_path);
    let bytes = std::fs::read(path).expect("read BLUETOOTH_TEST_SYSTEM_HIVE");
    let ours = ours(&devices_from_hive(
        &Hive::from_bytes(bytes).expect("BLUETOOTH_TEST_SYSTEM_HIVE is a valid REGF hive"),
    ));

    let Some(oracle) = oracle(path) else {
        eprintln!("SKIP: regipy oracle unavailable (pip install regipy) — real-hive differential");
        return;
    };

    assert_eq!(
        ours, oracle,
        "devices_from_hive disagrees with the independent regipy oracle on the real hive"
    );
}

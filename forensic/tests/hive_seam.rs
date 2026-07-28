//! Exercises the public [`bluetooth_forensic::devices_from_hive`] seam end-to-end against a
//! **synthetic in-memory `SYSTEM` hive** built byte-by-byte in [`common`] (a minimal but real REGF
//! image with a full `ControlSet001\Services\BTHPORT\Parameters\{Devices,Keys}` subtree).
//!
//! This is the library-level counterpart to `system_real.rs` (which drives the CLI against a real
//! hive, env-gated): it proves the hive-walk seam decodes device MAC / friendly `Name` /
//! `LastSeen` / `LastConnected` and the `Keys` link-key cross-reference **without** the private
//! binary, exactly as the downstream issen wrapper will call it.
//!
//! The fixture is **tier-3 on its own** (self-authored image + expected answer). The independent
//! oracle that lifts the *same* image to tier-2 (regipy re-reads it and reconciles) lives in
//! `hive_seam_oracle.rs`; the tier-1 real-hive oracle lives in `system_real.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use bluetooth_forensic::{devices_from_hive, BluetoothDevice};
use common::{build_system_hive, HiveBuilder, FT_LAST_CONNECTED, FT_LAST_SEEN};
use winreg_core::hive::Hive;

fn find<'a>(devices: &'a [BluetoothDevice], mac: &str) -> &'a BluetoothDevice {
    devices
        .iter()
        .find(|d| d.mac == mac)
        .unwrap_or_else(|| panic!("device {mac} not decoded from hive; got {devices:?}"))
}

#[test]
fn devices_from_hive_decodes_bthport_subtree() {
    let image = build_system_hive();
    let hive = Hive::from_bytes(image).expect("fixture is a valid REGF hive");

    let devices = devices_from_hive(&hive);

    // Two MAC subkeys decode; the non-MAC subkey is skipped.
    assert_eq!(devices.len(), 2, "got {devices:?}");

    let d1 = find(&devices, "AA:BB:CC:DD:EE:FF");
    assert_eq!(d1.name, "Sony WH-1000XM4");
    assert_eq!(d1.last_seen_filetime, Some(FT_LAST_SEEN));
    assert_eq!(d1.last_connected_filetime, Some(FT_LAST_CONNECTED));
    assert!(d1.has_link_key, "device 1 has a stored link key under Keys");

    let d2 = find(&devices, "00:1A:7D:DA:71:13");
    assert_eq!(d2.name, "Mouse");
    assert_eq!(d2.last_seen_filetime, None);
    assert_eq!(d2.last_connected_filetime, None);
    assert!(!d2.has_link_key, "device 2 has no stored link key");
}

#[test]
fn devices_from_hive_without_bthport_is_empty() {
    // A hive whose root has no ControlSet subtree yields no devices, not a panic.
    let mut b = HiveBuilder::new();
    let root_nk = b.nk("root", 0x0020 | 0x0004, 0xFFFF_FFFF, 0, 0xFFFF_FFFF, 0);
    let hive = Hive::from_bytes(b.finish(root_nk)).expect("valid empty hive");
    assert!(devices_from_hive(&hive).is_empty());
}

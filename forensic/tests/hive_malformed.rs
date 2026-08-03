//! Structurally damaged `SYSTEM` hives driven through the public
//! [`bluetooth_forensic::devices_from_hive`] seam.
//!
//! `hive_seam.rs` proves the happy path decodes correctly. This file covers the
//! opposite obligation: a hive is untrusted input, so every place the walk asks
//! the reader for a subkey or value list is a place that can fail on a truncated
//! or tampered image. Each fixture dangles exactly one offset, so the assertion
//! pins *which* recovery path ran rather than merely that nothing exploded.
//!
//! The invariant throughout is degrade, never abandon: an unreadable link-key
//! subtree costs the link-key annotation and nothing else — the devices it could
//! not annotate are still reported.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use bluetooth_forensic::devices_from_hive;
use common::{
    build_hive_with_unreadable_adapter_values, build_hive_with_unreadable_devices,
    build_hive_with_unreadable_keys, build_hive_without_keys,
};
use winreg_core::hive::Hive;

fn devices(image: Vec<u8>) -> Vec<bluetooth_forensic::BluetoothDevice> {
    let hive = Hive::from_bytes(image).expect("fixture is a valid REGF image");
    devices_from_hive(&hive)
}

#[test]
fn a_missing_keys_subtree_still_reports_the_devices() {
    // `Devices` present, `Keys` absent. The link-key lookup returns an empty set
    // and the device walk continues — losing an annotation must not lose evidence.
    let found = devices(build_hive_without_keys());
    assert_eq!(
        found.len(),
        1,
        "the paired device is still reported: {found:?}"
    );
    assert_eq!(found[0].mac, "AA:BB:CC:DD:EE:FF");
    assert!(
        !found[0].has_link_key,
        "no Keys subtree means no link key is known — not that one was found"
    );
}

#[test]
fn an_unreadable_devices_list_yields_nothing_and_does_not_panic() {
    // `Devices` exists but its subkey list dangles. There is no honest way to
    // enumerate it, so this control set contributes nothing at all.
    let found = devices(build_hive_with_unreadable_devices());
    assert!(
        found.is_empty(),
        "an unenumerable Devices key must yield no devices, not partial ones: {found:?}"
    );
}

#[test]
fn an_unreadable_keys_list_costs_only_the_link_key_annotation() {
    // `Keys` exists but its subkey list dangles. The device walk is independent
    // of it, so the device survives and simply carries no link key.
    let found = devices(build_hive_with_unreadable_keys());
    assert_eq!(found.len(), 1, "the device walk is unaffected: {found:?}");
    assert!(!found[0].has_link_key);
}

#[test]
fn an_unreadable_adapter_is_skipped_not_fatal() {
    // The single adapter under `Keys` has a dangling value list. Skipping it
    // leaves no known link keys, but the device is still reported.
    let found = devices(build_hive_with_unreadable_adapter_values());
    assert_eq!(found.len(), 1, "one broken adapter is not fatal: {found:?}");
    assert!(!found[0].has_link_key);
}

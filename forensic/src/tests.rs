//! Unit tests for the Bluetooth analyzer: the Tier-2 `FILETIME` oracle, the `audit` device→finding
//! mapping, and the `Observation` field mapping for both finding kinds. The whole-hive walk is
//! validated end-to-end in `tests/system_real.rs` (env-gated on a real `SYSTEM` hive + bthport.pl).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use bluetooth_core::decode_filetime;

fn device(
    mac: &str,
    name: &str,
    seen: Option<u64>,
    conn: Option<u64>,
    key: bool,
) -> BluetoothDevice {
    BluetoothDevice {
        mac: mac.to_string(),
        name: name.to_string(),
        last_seen_filetime: seen,
        last_connected_filetime: conn,
        has_link_key: key,
    }
}

// ── Tier-2: decode_filetime cross-checked against a Python `datetime` oracle ─────────────────
//
// Each row is `(FILETIME_u64, expected_utc)` computed independently in Python 3:
//
//   from datetime import datetime, timezone, timedelta
//   datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=ft//10)
//
// The values are second-aligned (multiples of 1e7 ticks) so the Python oracle and winreg-core's
// jiff conversion agree to the exact second. This exercises the real decode path bytes → u64
// (`bluetooth_core::decode_filetime`, i.e. bthport.pl's `unpack("VV")`) → UTC. See also
// `docs/validation.md`.
#[test]
fn decode_filetime_matches_python_datetime_oracle() {
    let cases: &[(u64, &str)] = &[
        // Unix-epoch boundary: FILETIME 116444736000000000 = 1601→1970 tick difference.
        (116_444_736_000_000_000, "1970-01-01T00:00:00Z"),
        (132_317_609_750_000_000, "2020-04-19T09:09:35Z"),
        (130_000_000_000_000_000, "2012-12-14T23:06:40Z"),
        (133_200_000_000_000_000, "2023-02-04T16:00:00Z"),
        (132_000_000_000_000_000, "2019-04-17T18:40:00Z"),
    ];
    for &(ft, expected) in cases {
        // Decode the 8 little-endian bytes exactly as the hive stores them.
        let decoded = decode_filetime(&ft.to_le_bytes()).expect("8 bytes decodes");
        assert_eq!(decoded, ft, "raw FILETIME round-trips");
        let rendered = render_time(Some(decoded)).expect("datable");
        assert_eq!(rendered, expected, "FILETIME {ft} → {expected}");
    }
}

#[test]
fn render_time_absent_or_undatable_is_none() {
    assert_eq!(render_time(None), None);
    // Zero / pre-1970 FILETIMEs are not datable (winreg-core returns None).
    assert_eq!(render_time(Some(0)), None);
    assert_eq!(render_time(Some(1)), None);
}

// ── audit: device → findings ────────────────────────────────────────────────

#[test]
fn audit_emits_one_paired_device_finding_per_device() {
    let devs = [
        device(
            "AA:BB:CC:DD:EE:FF",
            "Headset",
            Some(132_317_609_750_000_000),
            None,
            false,
        ),
        device("00:16:94:8D:12:34", "", None, None, false),
    ];
    let f = audit(&devs);
    let paired: Vec<_> = f
        .iter()
        .filter(|x| matches!(x, BluetoothFinding::PairedDevice { .. }))
        .collect();
    assert_eq!(paired.len(), 2);
    assert!(f
        .iter()
        .all(|x| matches!(x, BluetoothFinding::PairedDevice { .. })));
}

#[test]
fn audit_adds_link_key_finding_only_when_present() {
    let devs = [
        device("AA:BB:CC:DD:EE:FF", "Keyboard", None, None, true),
        device("00:16:94:8D:12:34", "Mouse", None, None, false),
    ];
    let f = audit(&devs);
    // 2 paired + 1 link-key = 3.
    assert_eq!(f.len(), 3);
    let keys: Vec<_> = f
        .iter()
        .filter_map(|x| match x {
            BluetoothFinding::LinkKeyStored { mac, .. } => Some(mac.as_str()),
            BluetoothFinding::PairedDevice { .. } => None,
        })
        .collect();
    assert_eq!(keys, ["AA:BB:CC:DD:EE:FF"]);
}

#[test]
fn audit_empty_input_is_empty() {
    assert!(audit(&[]).is_empty());
}

// ── Observation mapping ─────────────────────────────────────────────────────

#[test]
fn paired_device_observation_maps_all_fields() {
    let p = BluetoothFinding::PairedDevice {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        name: "Headset".to_string(),
        last_seen: Some("2020-04-19T09:09:35Z".to_string()),
        last_connected: None,
        has_link_key: true,
    };
    assert_eq!(p.severity(), Some(Severity::Info));
    assert_eq!(p.category(), Category::History);
    assert_eq!(p.code(), "BLUETOOTH-PAIRED-DEVICE");
    assert!(p.mitre().is_empty());
    let note = p.note();
    assert!(note.contains("AA:BB:CC:DD:EE:FF"));
    assert!(note.contains("(Headset)"));
    assert!(note.contains("LastSeen 2020-04-19T09:09:35Z"));
    assert!(note.contains("LastConnected unknown"));
    assert!(note.contains("A plaintext classic link key is stored"));
    assert!(note.contains("may reflect pairing time, not last use — corroborate"));
    let subs = p.subjects();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].scheme, "bluetooth");
    assert_eq!(subs[0].kind, "device");
    assert_eq!(subs[0].id, "AA:BB:CC:DD:EE:FF");
    assert_eq!(subs[0].label.as_deref(), Some("Headset"));
    let _ = to_finding(&p, "SYSTEM");
}

#[test]
fn paired_device_note_omits_name_and_key_when_absent() {
    let p = BluetoothFinding::PairedDevice {
        mac: "00:16:94:8D:12:34".to_string(),
        name: String::new(),
        last_seen: None,
        last_connected: Some("2019-04-17T18:40:00Z".to_string()),
        has_link_key: false,
    };
    let note = p.note();
    assert!(
        note.contains("device 00:16:94:8D:12:34."),
        "no name suffix: {note}"
    );
    assert!(!note.contains('('), "no parenthesised name: {note}");
    assert!(note.contains("LastSeen unknown"));
    assert!(note.contains("LastConnected 2019-04-17T18:40:00Z"));
    assert!(!note.contains("A plaintext classic link key"));
    // No name → the subject carries no label.
    assert_eq!(p.subjects()[0].label, None);
}

#[test]
fn link_key_observation_maps_all_fields() {
    let k = BluetoothFinding::LinkKeyStored {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        name: "Keyboard".to_string(),
    };
    assert_eq!(k.severity(), Some(Severity::Low));
    assert_eq!(k.category(), Category::Residue);
    assert_eq!(k.code(), "BLUETOOTH-LINK-KEY-STORED");
    assert_eq!(k.mitre(), &["T1552.002"]);
    let note = k.note();
    assert!(note.contains("AA:BB:CC:DD:EE:FF"));
    assert!(note.contains("(Keyboard)"));
    assert!(note.contains("extractable"));
    assert!(note.contains("impersonation"));
    assert_eq!(k.subjects()[0].label.as_deref(), Some("Keyboard"));
    let _ = to_finding(&k, "SYSTEM");
}

#[test]
fn link_key_note_without_name() {
    let k = BluetoothFinding::LinkKeyStored {
        mac: "00:16:94:8D:12:34".to_string(),
        name: String::new(),
    };
    assert!(!k.note().contains('('));
    assert_eq!(k.subjects()[0].label, None);
}

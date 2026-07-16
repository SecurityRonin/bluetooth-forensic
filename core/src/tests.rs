//! Unit tests for the pure Bluetooth value decoders. Inputs are synthetic `(name, bytes)` values
//! shaped exactly as `bthport.pl` reads them (12-hex subkey name, UTF-16LE / ASCII `Name`, 8-byte
//! little-endian `FILETIME`). The `FILETIME` decode is additionally cross-checked against a Python
//! `datetime` oracle in `../../forensic/src/tests.rs` (Tier-2), and the whole-hive walk is
//! validated end-to-end in `../../forensic/tests/system_real.rs` (env-gated on a real hive).

use super::*;

// ── parse_mac ───────────────────────────────────────────────────────────────

#[test]
fn parse_mac_formats_twelve_hex_as_colon_mac() {
    assert_eq!(
        parse_mac("aabbccddeeff"),
        Some("AA:BB:CC:DD:EE:FF".to_string())
    );
    // A real BTHPORT device subkey name.
    assert_eq!(
        parse_mac("0016948d1234"),
        Some("00:16:94:8D:12:34".to_string())
    );
}

#[test]
fn parse_mac_uppercases() {
    assert_eq!(
        parse_mac("0a1b2c3d4e5f"),
        Some("0A:1B:2C:3D:4E:5F".to_string())
    );
}

#[test]
fn parse_mac_rejects_wrong_length() {
    assert_eq!(parse_mac(""), None);
    assert_eq!(parse_mac("aabbccddeef"), None); // 11
    assert_eq!(parse_mac("aabbccddeeff0"), None); // 13
}

#[test]
fn parse_mac_rejects_non_hex() {
    assert_eq!(parse_mac("aabbccddeegg"), None); // 'g' not hex
    assert_eq!(parse_mac("zzzzzzzzzzzz"), None);
    // A 12-char string with a multibyte char has len() > 12 bytes → rejected, no panic.
    assert_eq!(parse_mac("aabbccddee€€"), None);
}

// ── decode_name ─────────────────────────────────────────────────────────────

#[test]
fn decode_name_reg_sz_utf16le_strips_trailing_nul() {
    // "Hi" as UTF-16LE with a trailing NUL terminator, exactly as REG_SZ stores it.
    let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
    assert_eq!(decode_name(&data, true), "Hi");
}

#[test]
fn decode_name_reg_sz_handles_non_ascii() {
    // "café" UTF-16LE (é = U+00E9), no terminator.
    let mut data = Vec::new();
    for u in "café".encode_utf16() {
        data.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(decode_name(&data, true), "café");
}

#[test]
fn decode_name_reg_sz_odd_length_drops_lone_byte() {
    // 5 bytes: two UTF-16 units + a dangling byte — must not panic, decodes the two units.
    let data = [0x41, 0x00, 0x42, 0x00, 0x99];
    assert_eq!(decode_name(&data, true), "AB");
}

#[test]
fn decode_name_reg_binary_ascii_strips_single_trailing_nul() {
    // REG_BINARY holding "Mouse\0".
    let data = b"Mouse\0";
    assert_eq!(decode_name(data, false), "Mouse");
}

#[test]
fn decode_name_reg_binary_without_nul_is_kept() {
    let data = b"Keyboard";
    assert_eq!(decode_name(data, false), "Keyboard");
}

#[test]
fn decode_name_empty_is_empty() {
    assert_eq!(decode_name(&[], true), "");
    assert_eq!(decode_name(&[], false), "");
}

// ── decode_filetime ─────────────────────────────────────────────────────────

#[test]
fn decode_filetime_reads_little_endian_u64() {
    // 01 02 03 04 05 06 07 08 → 0x0807_0605_0403_0201 (matches unpack("VV") low/high LE).
    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(decode_filetime(&data), Some(0x0807_0605_0403_0201));
}

#[test]
fn decode_filetime_reads_a_real_value() {
    // 2020-04-19T09:09:35Z, second-aligned FILETIME (see the Python oracle in forensic tests).
    let ft: u64 = 132_317_609_750_000_000;
    assert_eq!(decode_filetime(&ft.to_le_bytes()), Some(ft));
}

#[test]
fn decode_filetime_ignores_bytes_past_eight() {
    let mut data = 42u64.to_le_bytes().to_vec();
    data.extend_from_slice(&[0xff, 0xff]);
    assert_eq!(decode_filetime(&data), Some(42));
}

#[test]
fn decode_filetime_too_short_is_none() {
    assert_eq!(decode_filetime(&[]), None);
    assert_eq!(decode_filetime(&[0, 0, 0, 0, 0, 0, 0]), None); // 7 bytes
}

// ── decode_device ───────────────────────────────────────────────────────────

#[test]
fn decode_device_assembles_all_parts() {
    let name = [0x50, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x00, 0x00]; // "Pod\0" UTF-16LE
    let seen = 132_317_609_750_000_000u64.to_le_bytes();
    let conn = 132_000_000_000_000_000u64.to_le_bytes();
    let d = decode_device(
        "aabbccddeeff",
        Some((&name, true)),
        Some(&seen),
        Some(&conn),
        true,
    )
    .expect("valid device");
    assert_eq!(d.mac, "AA:BB:CC:DD:EE:FF");
    assert_eq!(d.name, "Pod");
    assert_eq!(d.last_seen_filetime, Some(132_317_609_750_000_000));
    assert_eq!(d.last_connected_filetime, Some(132_000_000_000_000_000));
    assert!(d.has_link_key);
}

#[test]
fn decode_device_bad_mac_is_none() {
    assert_eq!(decode_device("not-a-mac", None, None, None, false), None);
}

#[test]
fn decode_device_absent_values_default_cleanly() {
    let d = decode_device("0016948d1234", None, None, None, false).expect("valid device");
    assert_eq!(d.mac, "00:16:94:8D:12:34");
    assert_eq!(d.name, "");
    assert_eq!(d.last_seen_filetime, None);
    assert_eq!(d.last_connected_filetime, None);
    assert!(!d.has_link_key);
}

#[test]
fn decode_device_short_filetime_becomes_none() {
    let d =
        decode_device("aabbccddeeff", None, Some(&[0, 0, 0]), None, false).expect("valid device");
    assert_eq!(d.last_seen_filetime, None);
}

#[test]
fn device_default_is_empty() {
    let d = BluetoothDevice::default();
    assert!(d.mac.is_empty());
    assert!(d.name.is_empty());
    assert_eq!(d.last_seen_filetime, None);
    assert_eq!(d.last_connected_filetime, None);
    assert!(!d.has_link_key);
}

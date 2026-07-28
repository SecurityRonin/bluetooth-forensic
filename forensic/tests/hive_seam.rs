//! Exercises the public [`bluetooth_forensic::devices_from_hive`] seam end-to-end against a
//! **synthetic in-memory `SYSTEM` hive** built byte-by-byte here (a minimal but real REGF image with
//! a full `ControlSet001\Services\BTHPORT\Parameters\{Devices,Keys}` subtree).
//!
//! This is the library-level counterpart to `system_real.rs` (which drives the CLI against a real
//! hive, env-gated): it proves the hive-walk seam decodes device MAC / friendly `Name` /
//! `LastSeen` / `LastConnected` and the `Keys` link-key cross-reference **without** the private
//! binary, exactly as the downstream issen wrapper will call it.
//!
//! The fixture is **Tier-3** (self-authored image + expected answer): it validates that the seam
//! walks the documented `bthport.pl` paths and wires `bluetooth_core::decode_device` correctly. The
//! Tier-1 oracle (RegRipper's `bthport.pl` on a genuine hive) lives in `system_real.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bluetooth_forensic::{devices_from_hive, BluetoothDevice};
use winreg_core::hive::Hive;

// FILETIMEs cross-checked against a Python `datetime` oracle in forensic/src/tests.rs.
const FT_LAST_SEEN: u64 = 132_317_609_750_000_000; // 2020-04-19T09:09:35Z
const FT_LAST_CONNECTED: u64 = 133_200_000_000_000_000; // 2023-02-04T16:00:00Z

const NK_COMP_NAME: u16 = 0x0020;
const NK_HIVE_ENTRY: u16 = 0x0004;
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const NULL: u32 = 0xFFFF_FFFF;

/// Minimal REGF hive-image writer: appends cells into a single hbin and hands back cell offsets.
struct HiveBuilder {
    /// Hive bins area. The first 32 bytes are the hbin header; cells follow (so the first cell lands
    /// at cell offset 32, matching a real hive).
    body: Vec<u8>,
}

impl HiveBuilder {
    fn new() -> Self {
        let mut body = vec![0u8; 32];
        body[0..4].copy_from_slice(b"hbin");
        // body[4..8] = hbin offset (0); body[8..12] = size, patched in `finish`.
        Self { body }
    }

    /// Append one allocated cell whose bytes (after the 4-byte size header) are `payload`; return its
    /// cell offset relative to hive-bins-data start.
    fn alloc(&mut self, payload: &[u8]) -> u32 {
        let cell_offset = self.body.len() as u32;
        let raw = 4 + payload.len();
        let total = (raw + 7) & !7; // cells are 8-byte aligned
        let size = -(i32::try_from(total).unwrap()); // negative = allocated
        self.body.extend_from_slice(&size.to_le_bytes());
        self.body.extend_from_slice(payload);
        self.body.resize(self.body.len() + (total - raw), 0);
        cell_offset
    }

    /// A raw data cell (value data: no signature).
    fn data(&mut self, bytes: &[u8]) -> u32 {
        self.alloc(bytes)
    }

    /// A `vk` (value) cell pointing at a non-resident data cell.
    fn vk(&mut self, name: &str, ty: u32, data_size: u32, data_offset: u32) -> u32 {
        let name_bytes = name.as_bytes();
        let comp = u16::from(!name.is_empty()); // 0x0001 COMP_NAME when named
        let mut p = vec![0u8; 20 + name_bytes.len()];
        p[0..2].copy_from_slice(b"vk");
        p[2..4].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        p[4..8].copy_from_slice(&data_size.to_le_bytes()); // top bit clear = non-resident
        p[8..12].copy_from_slice(&data_offset.to_le_bytes());
        p[12..16].copy_from_slice(&ty.to_le_bytes());
        p[16..18].copy_from_slice(&comp.to_le_bytes());
        p[20..20 + name_bytes.len()].copy_from_slice(name_bytes);
        self.alloc(&p)
    }

    /// A value-list cell: a bare array of `vk` offsets (no signature).
    fn value_list(&mut self, vks: &[u32]) -> u32 {
        let mut p = Vec::new();
        for &off in vks {
            p.extend_from_slice(&off.to_le_bytes());
        }
        self.alloc(&p)
    }

    /// An `li` (index leaf) subkey list.
    fn li(&mut self, subkeys: &[u32]) -> u32 {
        let mut p = Vec::new();
        p.extend_from_slice(b"li");
        p.extend_from_slice(&(subkeys.len() as u16).to_le_bytes());
        for &off in subkeys {
            p.extend_from_slice(&off.to_le_bytes());
        }
        self.alloc(&p)
    }

    /// An `nk` (key node) cell.
    fn nk(
        &mut self,
        name: &str,
        flags: u16,
        subkeys_list: u32,
        subkey_count: u32,
        value_list: u32,
        value_count: u32,
    ) -> u32 {
        let name_bytes = name.as_bytes();
        let mut p = vec![0u8; 76 + name_bytes.len()];
        p[0..2].copy_from_slice(b"nk");
        p[2..4].copy_from_slice(&flags.to_le_bytes());
        p[20..24].copy_from_slice(&subkey_count.to_le_bytes());
        p[28..32].copy_from_slice(&subkeys_list.to_le_bytes());
        p[32..36].copy_from_slice(&NULL.to_le_bytes()); // volatile subkeys list
        p[36..40].copy_from_slice(&value_count.to_le_bytes());
        p[40..44].copy_from_slice(&value_list.to_le_bytes());
        p[44..48].copy_from_slice(&NULL.to_le_bytes()); // security
        p[48..52].copy_from_slice(&NULL.to_le_bytes()); // class name
        p[72..74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        p[76..76 + name_bytes.len()].copy_from_slice(name_bytes);
        self.alloc(&p)
    }

    /// A key with no values and no subkeys (an interior path node gets its subkeys list separately).
    fn key(&mut self, name: &str, subkeys_list: u32, subkey_count: u32) -> u32 {
        self.nk(name, NK_COMP_NAME, subkeys_list, subkey_count, NULL, 0)
    }

    /// Seal the image: pad the hbin to a 4096 multiple, patch its size, prepend the base block.
    fn finish(mut self, root_offset: u32) -> Vec<u8> {
        let bins_size = self.body.len().div_ceil(4096) * 4096;
        self.body.resize(bins_size, 0);
        self.body[8..12].copy_from_slice(&(bins_size as u32).to_le_bytes());

        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"regf");
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // primary seq
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes()); // secondary seq
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version = 1.5
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // format
        buf[0x24..0x28].copy_from_slice(&root_offset.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&(bins_size as u32).to_le_bytes());
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
        let checksum = compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        buf.extend_from_slice(&self.body);
        buf
    }
}

/// REGF base-block XOR-32 checksum (winreg-format `BaseBlock::compute_checksum`).
fn compute_checksum(header: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for i in 0..127 {
        let o = i * 4;
        sum ^= u32::from_le_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]);
    }
    match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    }
}

/// UTF-16LE bytes of `s` with a trailing NUL unit (how `REG_SZ` `Name` values are stored).
fn utf16le_z(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Build a SYSTEM hive with two paired Bluetooth devices under ControlSet001, one of which has a
/// stored classic link key, plus a non-MAC subkey that must be skipped.
fn build_system_hive() -> Vec<u8> {
    let mut b = HiveBuilder::new();

    // ── Device 1: AA:BB:CC:DD:EE:FF, "Sony WH-1000XM4", both timestamps, link key present ──
    let d1_name_bytes = utf16le_z("Sony WH-1000XM4");
    let d1_name_data = b.data(&d1_name_bytes);
    let d1_seen_data = b.data(&FT_LAST_SEEN.to_le_bytes());
    let d1_conn_data = b.data(&FT_LAST_CONNECTED.to_le_bytes());
    let d1_name_vk = b.vk("Name", REG_SZ, d1_name_bytes.len() as u32, d1_name_data);
    let d1_seen_vk = b.vk("LastSeen", REG_BINARY, 8, d1_seen_data);
    let d1_conn_vk = b.vk("LastConnected", REG_BINARY, 8, d1_conn_data);
    let d1_values = b.value_list(&[d1_name_vk, d1_seen_vk, d1_conn_vk]);
    let d1_nk = b.nk("aabbccddeeff", NK_COMP_NAME, NULL, 0, d1_values, 3);

    // ── Device 2: 00:1A:7D:DA:71:13, REG_BINARY "Mouse\0", no timestamps, no link key ──
    let d2_name_bytes = b"Mouse\0";
    let d2_name_data = b.data(d2_name_bytes);
    let d2_name_vk = b.vk("Name", REG_BINARY, d2_name_bytes.len() as u32, d2_name_data);
    let d2_values = b.value_list(&[d2_name_vk]);
    let d2_nk = b.nk("001a7dda7113", NK_COMP_NAME, NULL, 0, d2_values, 1);

    // ── A non-device subkey that parse_mac must reject ──
    let junk_nk = b.key("NotAMacSubkey", NULL, 0);

    let devices_li = b.li(&[d1_nk, d2_nk, junk_nk]);
    let devices_nk = b.key("Devices", devices_li, 3);

    // ── Keys subtree: adapter 11:22:33:44:55:66 holds device-1's 16-byte link key ──
    let linkkey_data = b.data(&[0xAA; 16]);
    let linkkey_vk = b.vk("aabbccddeeff", REG_BINARY, 16, linkkey_data);
    let adapter_values = b.value_list(&[linkkey_vk]);
    let adapter_nk = b.nk("112233445566", NK_COMP_NAME, NULL, 0, adapter_values, 1);
    let keys_li = b.li(&[adapter_nk]);
    let keys_nk = b.key("Keys", keys_li, 1);

    // ── Parameters → BTHPORT → Services → ControlSet001 → root ──
    let params_li = b.li(&[devices_nk, keys_nk]);
    let params_nk = b.key("Parameters", params_li, 2);
    let bthport_li = b.li(&[params_nk]);
    let bthport_nk = b.key("BTHPORT", bthport_li, 1);
    let services_li = b.li(&[bthport_nk]);
    let services_nk = b.key("Services", services_li, 1);
    let cs_li = b.li(&[services_nk]);
    let cs_nk = b.key("ControlSet001", cs_li, 1);
    let root_li = b.li(&[cs_nk]);
    let root_nk = b.nk("root", NK_COMP_NAME | NK_HIVE_ENTRY, root_li, 1, NULL, 0);

    b.finish(root_nk)
}

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
    let root_nk = b.nk("root", NK_COMP_NAME | NK_HIVE_ENTRY, NULL, 0, NULL, 0);
    let hive = Hive::from_bytes(b.finish(root_nk)).expect("valid empty hive");
    assert!(devices_from_hive(&hive).is_empty());
}

//! Shared test support: a minimal byte-exact REGF `SYSTEM` hive writer and the canonical
//! two-device `BTHPORT` fixture, consumed by both the tier-3 seam test (`hive_seam.rs`) and the
//! tier-2 independent-oracle differential (`hive_seam_oracle.rs`).
//!
//! The image is a real (if minimal) REGF v1.5 hive: a base block with a valid XOR-32 checksum over
//! a single hbin holding `nk` / `vk` / `li` / value-list / data cells. It is hand-built so the
//! expected answer is *derivable from the documented construction* — but a hand-built fixture only
//! encodes the quirks the author thought of, so `hive_seam_oracle.rs` re-reads the very same bytes
//! with an **independent** REGF parser (regipy) and reconciles, lifting the seam from tier-3
//! (self-authored fixture + self-authored answer) to tier-2 (answer confirmed by an independent
//! oracle on the author's chosen scenario).
#![allow(dead_code)] // each integration-test binary uses a subset of these items

// FILETIMEs cross-checked against a Python `datetime` oracle in forensic/src/tests.rs.
pub const FT_LAST_SEEN: u64 = 132_317_609_750_000_000; // 2020-04-19T09:09:35Z
pub const FT_LAST_CONNECTED: u64 = 133_200_000_000_000_000; // 2023-02-04T16:00:00Z

const NK_COMP_NAME: u16 = 0x0020;
const NK_HIVE_ENTRY: u16 = 0x0004;
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const NULL: u32 = 0xFFFF_FFFF;

/// A reserved root `nk` cell whose subkey list is patched in once its children exist.
pub struct RootSlot {
    pub cell_offset: u32,
    subkey_count_at: usize,
    subkeys_list_at: usize,
}

/// One device the canonical fixture is expected to yield — the answer key an independent oracle must
/// reproduce.
pub struct ExpectedDevice {
    pub mac: String,
    pub name: String,
    pub last_seen: Option<u64>,
    pub last_connected: Option<u64>,
    pub has_link_key: bool,
}

/// The two paired devices `build_system_hive` encodes (device order-independent).
pub fn expected_devices() -> Vec<ExpectedDevice> {
    vec![
        ExpectedDevice {
            mac: "AA:BB:CC:DD:EE:FF".into(),
            name: "Sony WH-1000XM4".into(),
            last_seen: Some(FT_LAST_SEEN),
            last_connected: Some(FT_LAST_CONNECTED),
            has_link_key: true,
        },
        ExpectedDevice {
            mac: "00:1A:7D:DA:71:13".into(),
            name: "Mouse".into(),
            last_seen: None,
            last_connected: None,
            has_link_key: false,
        },
    ]
}

/// Minimal REGF hive-image writer: appends cells into a single hbin and hands back cell offsets.
pub struct HiveBuilder {
    /// Hive bins area. The first 32 bytes are the hbin header; cells follow (so the first cell lands
    /// at cell offset 32, matching a real hive).
    body: Vec<u8>,
}

impl HiveBuilder {
    pub fn new() -> Self {
        let mut body = vec![0u8; 32];
        body[0..4].copy_from_slice(b"hbin");
        // body[4..8] = hbin offset (0); body[8..12] = size, patched in `finish`.
        Self { body }
    }

    /// Append one allocated cell whose bytes (after the 4-byte size header) are `payload`; return its
    /// cell offset relative to hive-bins-data start.
    pub fn alloc(&mut self, payload: &[u8]) -> u32 {
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
    pub fn data(&mut self, bytes: &[u8]) -> u32 {
        self.alloc(bytes)
    }

    /// A `vk` (value) cell pointing at a non-resident data cell.
    pub fn vk(&mut self, name: &str, ty: u32, data_size: u32, data_offset: u32) -> u32 {
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
    pub fn value_list(&mut self, vks: &[u32]) -> u32 {
        let mut p = Vec::new();
        for &off in vks {
            p.extend_from_slice(&off.to_le_bytes());
        }
        self.alloc(&p)
    }

    /// An `li` (index leaf) subkey list.
    pub fn li(&mut self, subkeys: &[u32]) -> u32 {
        let mut p = Vec::new();
        p.extend_from_slice(b"li");
        p.extend_from_slice(&(subkeys.len() as u16).to_le_bytes());
        for &off in subkeys {
            p.extend_from_slice(&off.to_le_bytes());
        }
        self.alloc(&p)
    }

    /// An `nk` (key node) cell.
    pub fn nk(
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
    pub fn key(&mut self, name: &str, subkeys_list: u32, subkey_count: u32) -> u32 {
        self.nk(name, NK_COMP_NAME, subkeys_list, subkey_count, NULL, 0)
    }

    /// Reserve the root `nk` cell **as the first cell in the hbin**, with its subkey list left
    /// unset, and return a [`RootSlot`] for later back-patching.
    ///
    /// A real hive's root key is the first cell of the first hbin, and independent parsers (e.g.
    /// regipy) locate the root that way rather than via the base block's `root_key_offset`. Emitting
    /// the root first — then patching in its subkey list once the children exist — keeps the image
    /// faithful to both our `winreg-core` reader (which follows `root_key_offset`) and a
    /// first-cell-based parser.
    pub fn reserve_root(&mut self, name: &str, flags: u16) -> RootSlot {
        let cell_offset = self.nk(name, flags, NULL, 0, NULL, 0);
        // Payload begins after the 4-byte cell-size header; within it subkey_count is at 20 and the
        // stable subkeys-list offset at 28 (see `nk`).
        let payload = (cell_offset + 4) as usize;
        RootSlot {
            cell_offset,
            subkey_count_at: payload + 20,
            subkeys_list_at: payload + 28,
        }
    }

    /// Fill in a reserved root's subkey list and count once the children have been allocated.
    pub fn patch_root(&mut self, slot: &RootSlot, subkeys_list: u32, subkey_count: u32) {
        self.body[slot.subkey_count_at..slot.subkey_count_at + 4]
            .copy_from_slice(&subkey_count.to_le_bytes());
        self.body[slot.subkeys_list_at..slot.subkeys_list_at + 4]
            .copy_from_slice(&subkeys_list.to_le_bytes());
    }

    /// Seal the image: pad the hbin to a 4096 multiple, patch its size, prepend the base block.
    pub fn finish(mut self, root_offset: u32) -> Vec<u8> {
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

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
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
/// stored classic link key, plus a non-MAC subkey that must be skipped. See [`expected_devices`] for
/// the answer key.
pub fn build_system_hive() -> Vec<u8> {
    let mut b = HiveBuilder::new();

    // Root is the first cell (real-hive layout); its subkey list is patched in at the end.
    let root = b.reserve_root("root", NK_COMP_NAME | NK_HIVE_ENTRY);

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
    b.patch_root(&root, root_li, 1);

    b.finish(root.cell_offset)
}

/// A structurally plausible but dangling cell offset: it parses as an offset and
/// points at nothing, which is what a truncated or tampered hive looks like in
/// practice. Used to drive the `subkeys()` / `values()` error paths that a
/// well-formed fixture can never reach.
const DANGLING: u32 = 0x00BA_DBAD;

/// Wrap caller-built `Parameters` children in the
/// `ControlSet001\Services\BTHPORT\Parameters` chain and seal the image.
fn bthport_hive(make_children: impl FnOnce(&mut HiveBuilder) -> Vec<u32>) -> Vec<u8> {
    let mut b = HiveBuilder::new();
    let root = b.reserve_root("root", NK_COMP_NAME | NK_HIVE_ENTRY);
    let children = make_children(&mut b);
    let count = children.len() as u32;
    let params_li = b.li(&children);
    let params_nk = b.key("Parameters", params_li, count);
    let bthport_li = b.li(&[params_nk]);
    let bthport_nk = b.key("BTHPORT", bthport_li, 1);
    let services_li = b.li(&[bthport_nk]);
    let services_nk = b.key("Services", services_li, 1);
    let cs_li = b.li(&[services_nk]);
    let cs_nk = b.key("ControlSet001", cs_li, 1);
    let root_li = b.li(&[cs_nk]);
    b.patch_root(&root, root_li, 1);
    b.finish(root.cell_offset)
}

/// `Devices` present, `Keys` absent — a device that was paired but whose link key
/// was removed (or a hive captured before any key was stored).
pub fn build_hive_without_keys() -> Vec<u8> {
    bthport_hive(|b| {
        let dev = b.key("aabbccddeeff", NULL, 0);
        let devices_li = b.li(&[dev]);
        let devices_nk = b.key("Devices", devices_li, 1);
        vec![devices_nk]
    })
}

/// `Devices` exists but its subkey list dangles — the device enumeration must be
/// abandoned for this control set rather than trusted or panicked on.
pub fn build_hive_with_unreadable_devices() -> Vec<u8> {
    bthport_hive(|b| {
        let devices_nk = b.key("Devices", DANGLING, 3);
        let keys_li = b.li(&[]);
        let keys_nk = b.key("Keys", keys_li, 0);
        vec![devices_nk, keys_nk]
    })
}

/// `Keys` exists but its subkey list dangles — the link-key cross-reference must
/// degrade to "no keys known", never take the device walk down with it.
pub fn build_hive_with_unreadable_keys() -> Vec<u8> {
    bthport_hive(|b| {
        let dev = b.key("aabbccddeeff", NULL, 0);
        let devices_li = b.li(&[dev]);
        let devices_nk = b.key("Devices", devices_li, 1);
        let keys_nk = b.key("Keys", DANGLING, 1);
        vec![devices_nk, keys_nk]
    })
}

/// A `Keys` adapter whose value list dangles — one unreadable adapter must be
/// skipped, leaving any sibling adapters still readable.
pub fn build_hive_with_unreadable_adapter_values() -> Vec<u8> {
    bthport_hive(|b| {
        let dev = b.key("aabbccddeeff", NULL, 0);
        let devices_li = b.li(&[dev]);
        let devices_nk = b.key("Devices", devices_li, 1);

        let broken = b.nk("112233445566", NK_COMP_NAME, NULL, 0, DANGLING, 1);
        let keys_li = b.li(&[broken]);
        let keys_nk = b.key("Keys", keys_li, 1);
        vec![devices_nk, keys_nk]
    })
}

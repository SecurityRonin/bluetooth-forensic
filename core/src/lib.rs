//! Pure-Rust read-only decoder for Windows **Bluetooth** pairing/connection evidence held in the
//! `SYSTEM` hive.
//!
//! When a Windows host pairs with a Bluetooth device, the MS Bluetooth stack records the device
//! under:
//!
//! ```text
//! SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\{deviceMAC}
//! ```
//!
//! one subkey per paired device. The subkey **name** is the device MAC as 12 hex characters (6
//! bytes, no separators); under it are the friendly `Name` and the `LastSeen` / `LastConnected`
//! timestamps. A plaintext classic link key, when present, lives separately under
//! `…\BTHPORT\Parameters\Keys\{adapterMAC}\{deviceMAC}`.
//!
//! This crate is a *decoder primitive*: it turns a subkey name and raw value bytes into a
//! [`BluetoothDevice`] and never touches the registry (the [`bluetooth-forensic`] crate reads the
//! values out of a hive with `winreg-core`). Like the fleet's other decoders it is
//! `#![forbid(unsafe_code)]` and **panic-free**: every multi-byte read is bounds-checked and odd
//! lengths yield a shorter decode, never a panic.
//!
//! Byte handling is grounded in RegRipper's `bthport.pl` plugin (`keydet89/RegRipper3.0`):
//! - the subkey name is the device unique ID (`bthport.pl` L66, `get_name`);
//! - `Name` is the friendly name (L72, `get_value("Name")`);
//! - `LastSeen` / `LastConnected` are 8-byte `FILETIME`s read as two little-endian `u32`s
//!   (L77/L82, `unpack("VV", …)`), i.e. one little-endian `u64`.
//!
//! [`bluetooth-forensic`]: https://crates.io/crates/bluetooth-forensic

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// One decoded Bluetooth pairing record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BluetoothDevice {
    /// The device MAC, formatted `AA:BB:CC:DD:EE:FF` from the 12-hex subkey name.
    pub mac: String,
    /// The device friendly name (`Name` value), or empty when the value is absent.
    pub name: String,
    /// `LastSeen` as a raw Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC), or `None` when
    /// the value is absent or shorter than 8 bytes.
    pub last_seen_filetime: Option<u64>,
    /// `LastConnected` as a raw Windows `FILETIME`, or `None` when absent/too short.
    pub last_connected_filetime: Option<u64>,
    /// Whether a plaintext classic link key is stored for this device under
    /// `…\BTHPORT\Parameters\Keys\{adapterMAC}\{deviceMAC}`. The key bytes themselves are never
    /// decoded or carried by this crate — only their presence.
    pub has_link_key: bool,
}

/// Parse a `BTHPORT\…\Devices` subkey name (a 12-hex device MAC, no separators) into the canonical
/// upper-case colon form `AA:BB:CC:DD:EE:FF`.
///
/// Returns `None` for anything that is not exactly 12 ASCII hex characters (matching `bthport.pl`'s
/// use of the raw subkey name as the device unique ID — L66). Never panics.
#[must_use]
pub fn parse_mac(_subkey_name: &str) -> Option<String> {
    None // RED stub
}

/// Decode a `Name` value into the device friendly name.
///
/// Real hives store this two ways, so both are handled (robustness — see `bthport.pl` L72, which
/// takes the value data as-is): when `is_reg_sz` the bytes are UTF-16LE (a trailing NUL terminator
/// is stripped); otherwise the value is `REG_BINARY` holding an ASCII/UTF-8 string with a single
/// trailing `0x00`, which is stripped. Invalid encodings are replaced (`from_utf16_lossy` /
/// `from_utf8_lossy`); an odd byte length drops the trailing lone byte rather than panicking.
#[must_use]
pub fn decode_name(_data: &[u8], _is_reg_sz: bool) -> String {
    String::new() // RED stub
}

/// Decode an 8-byte little-endian `FILETIME` value (`LastSeen` / `LastConnected`).
///
/// Reads the first 8 bytes as one little-endian `u64` — equivalent to `bthport.pl`'s
/// `unpack("VV", …)` of two little-endian `u32`s (low32, high32) (L77/L82). Returns `None` when
/// fewer than 8 bytes are available; never panics.
#[must_use]
pub fn decode_filetime(_data: &[u8]) -> Option<u64> {
    None // RED stub
}

/// Assemble a [`BluetoothDevice`] from a device subkey name and the raw bytes of its values.
///
/// `name` is the `Name` value's `(bytes, is_reg_sz)` when present; `last_seen` / `last_connected`
/// are the raw `FILETIME` value bytes when present; `has_link_key` is whether a link key exists for
/// this device under the `Keys` subtree. Returns `None` only when `subkey_name` is not a valid
/// 12-hex device MAC (so a non-device subkey is skipped). Never panics.
#[must_use]
pub fn decode_device(
    _subkey_name: &str,
    _name: Option<(&[u8], bool)>,
    _last_seen: Option<&[u8]>,
    _last_connected: Option<&[u8]>,
    _has_link_key: bool,
) -> Option<BluetoothDevice> {
    None // RED stub
}

#[cfg(test)]
mod tests;

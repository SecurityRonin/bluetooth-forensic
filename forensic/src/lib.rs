//! Windows **Bluetooth** forensic analyzer.
//!
//! The MS Bluetooth stack records every paired device under `SYSTEM\…\BTHPORT\Parameters\Devices\
//! {deviceMAC}` — the device MAC, its friendly `Name`, and the `LastSeen` / `LastConnected`
//! timestamps. This crate takes the decoded [`BluetoothDevice`] records (from [`bluetooth_core`])
//! and turns them into [`forensicnomicon`] findings.
//!
//! It is **evidence-first**: every paired device becomes an `Info` `BLUETOOTH-PAIRED-DEVICE`
//! finding stating the MAC, name, and last-seen/last-connected times, with an explicit caveat that
//! those timestamps may reflect *pairing* time rather than last use. The one graded signal is a
//! `Low` `BLUETOOTH-LINK-KEY-STORED` finding when a plaintext classic link key is stored for the
//! device (extractable credential material that enables impersonation — MITRE `T1552.002`,
//! Credentials in Registry). No High-severity verdicts: the hive establishes that a device was
//! paired, not what was done with it.
//!
//! Reading the values out of a `SYSTEM` hive is `winreg-core`'s job; the bundled `bluetooth4n6`
//! binary wires the two together (hive → [`bluetooth_core::decode_device`] → this crate).

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::Cursor;

use bluetooth_core::{decode_device, parse_mac};
use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use winreg_core::hive::Hive;
use winreg_core::key::{filetime_to_datetime, Key};

// Re-export the core type that appears in this crate's public API.
pub use bluetooth_core::BluetoothDevice;

/// Control sets to walk. `bthport.pl` resolves the active set via `Select\Current`; walking both
/// numbered sets is equivalent and robust (a hive populates one or both, and an absent set is
/// skipped).
const CONTROL_SETS: &[&str] = &["ControlSet001", "ControlSet002"];

/// Walk a `SYSTEM` hive's MS Bluetooth stack and decode every paired device.
///
/// For each control set this opens `…\Services\BTHPORT\Parameters\Devices`, treats each subkey as a
/// device MAC (the subkey name), reads its `Name` / `LastSeen` / `LastConnected` values, and cross-
/// references the sibling `…\Parameters\Keys` subtree for a stored classic link key — feeding each
/// device to [`bluetooth_core::decode_device`]. Paths follow RegRipper's `bthport.pl`
/// (`keydet89/RegRipper3.0`): the device subkeys under `Services\BTHPORT\Parameters\Devices` (L56),
/// the subkey name as the device MAC (L66), and the `Name` / `LastSeen` / `LastConnected` values
/// (L72/L77/L82).
///
/// The caller supplies an already-opened [`Hive`], so the bootstrap (REGF signature, checksum, and
/// version) is validated before this runs. Within the walk a malformed/absent key or value is a
/// per-artifact miss: it is skipped so a corrupt subtree yields the readable devices rather than
/// aborting the whole extraction. Non-MAC subkeys under `Devices` are skipped. Never panics.
#[must_use]
pub fn devices_from_hive(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<BluetoothDevice> {
    let mut out = Vec::new();
    for cs in CONTROL_SETS {
        let devices_path = format!(r"{cs}\Services\BTHPORT\Parameters\Devices");
        let Ok(Some(devices)) = hive.open_key(&devices_path) else {
            continue;
        };
        let link_key_macs = link_key_macs(hive, cs);
        let Ok(device_keys) = devices.subkeys() else {
            continue;
        };
        for dev_key in device_keys {
            let subkey_name = dev_key.name();
            let Some(mac) = parse_mac(&subkey_name) else {
                continue; // not a device-MAC subkey
            };
            let name = read_name_value(&dev_key);
            let last_seen = read_raw(&dev_key, "LastSeen");
            let last_connected = read_raw(&dev_key, "LastConnected");
            if let Some(device) = decode_device(
                &subkey_name,
                name.as_ref().map(|(d, sz)| (d.as_slice(), *sz)),
                last_seen.as_deref(),
                last_connected.as_deref(),
                link_key_macs.contains(&mac),
            ) {
                out.push(device);
            }
        }
    }
    out
}

/// Read the `Name` value's `(bytes, is_reg_sz)`, or `None` when absent/unreadable. `is_reg_sz` is
/// true for `REG_SZ`/`REG_EXPAND_SZ` (UTF-16LE), false for `REG_BINARY` (ASCII with trailing NUL).
fn read_name_value(key: &Key<'_, Hive<Cursor<Vec<u8>>>>) -> Option<(Vec<u8>, bool)> {
    let value = key.value("Name").ok()??;
    let is_reg_sz = matches!(value.data_type().name(), "REG_SZ" | "REG_EXPAND_SZ");
    let data = value.raw_data().ok()?;
    Some((data, is_reg_sz))
}

/// Read a value's raw bytes by name, or `None` when the value is absent/unreadable.
fn read_raw(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Option<Vec<u8>> {
    let value = key.value(name).ok()??;
    value.raw_data().ok()
}

/// The set of device MACs that have a stored classic link key under `{cs}\…\BTHPORT\Parameters\Keys`.
///
/// Under each adapter subkey the link keys are `REG_BINARY` values named by the remote device MAC.
/// The key bytes themselves are never read or retained — only the MAC (presence). An absent or
/// unreadable `Keys` subtree yields an empty set.
fn link_key_macs(hive: &Hive<Cursor<Vec<u8>>>, cs: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let keys_path = format!(r"{cs}\Services\BTHPORT\Parameters\Keys");
    let Ok(Some(keys)) = hive.open_key(&keys_path) else {
        return out;
    };
    let Ok(adapters) = keys.subkeys() else {
        return out;
    };
    for adapter in adapters {
        let Ok(values) = adapter.values() else {
            continue;
        };
        for value in values {
            if let Some(mac) = parse_mac(&value.name()) {
                out.insert(mac);
            }
        }
    }
    out
}

/// A Bluetooth finding — either the neutral per-device evidence record or the graded stored-link-key
/// signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BluetoothFinding {
    /// One paired device, reported as evidence (Info). Timestamps are pre-rendered to a
    /// human-readable UTC string (`None` when the value was absent or undatable).
    PairedDevice {
        /// Device MAC (`AA:BB:CC:DD:EE:FF`).
        mac: String,
        /// Friendly name, or empty when the `Name` value was absent.
        name: String,
        /// `LastSeen` rendered as UTC, or `None`.
        last_seen: Option<String>,
        /// `LastConnected` rendered as UTC, or `None`.
        last_connected: Option<String>,
        /// Whether a plaintext link key is stored for this device.
        has_link_key: bool,
    },
    /// A plaintext classic link key is stored for this device (Low) — extractable credential
    /// material that enables impersonation of the pairing.
    LinkKeyStored {
        /// Device MAC the stored key belongs to.
        mac: String,
        /// Friendly name, or empty when absent.
        name: String,
    },
}

/// Turn decoded devices into findings: one [`BluetoothFinding::PairedDevice`] per device, plus a
/// [`BluetoothFinding::LinkKeyStored`] for each device that has a stored link key.
#[must_use]
pub fn audit(devices: &[BluetoothDevice]) -> Vec<BluetoothFinding> {
    let mut out = Vec::new();
    for d in devices {
        out.push(BluetoothFinding::PairedDevice {
            mac: d.mac.clone(),
            name: d.name.clone(),
            last_seen: render_time(d.last_seen_filetime),
            last_connected: render_time(d.last_connected_filetime),
            has_link_key: d.has_link_key,
        });
        if d.has_link_key {
            out.push(BluetoothFinding::LinkKeyStored {
                mac: d.mac.clone(),
                name: d.name.clone(),
            });
        }
    }
    out
}

/// FILETIME epoch offset (1601-01-01 → 1970-01-01) in 100 ns ticks — the documented Windows
/// constant, mirrored here to bound-check a raw value without a round-trip through the converter.
const FILETIME_UNIX_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Pass a raw `FILETIME` through only when it lands inside jiff's representable instant range;
/// otherwise `None` ("undatable").
///
/// A crafted, astronomically large `FILETIME` (e.g. `0xBBBB_BBBB_BBBB_BBBB`, ~year 44500) decodes
/// to a second count that fits an `i64` but exceeds jiff's year-9999 `Timestamp` bound. `jiff`'s
/// `Timestamp::from_nanosecond` only range-checks the `i64` fit, then constructs via a
/// debug-asserting `new_unchecked` — so in a `debug_assertions` build (cargo-fuzz's default) that
/// value panics *inside* the converter instead of yielding `Err`, and `winreg_core`'s `.ok()`
/// cannot catch a panic. Gating on the same nanosecond arithmetic the converter uses keeps every
/// undatable value from reaching it. (The upstream defect is jiff's incomplete bound check; this
/// guard is the parser distrusting attacker-controlled input, per the panic-free standard.)
fn datable_filetime(filetime: u64) -> Option<u64> {
    let ticks = filetime.checked_sub(FILETIME_UNIX_EPOCH_DIFF)?;
    let nanos = i128::from(ticks).checked_mul(100)?;
    (nanos <= jiff::Timestamp::MAX.as_nanosecond()).then_some(filetime)
}

/// Render a raw `FILETIME` to a human-readable UTC string, or `None` when absent/undatable.
#[must_use]
pub fn render_time(filetime: Option<u64>) -> Option<String> {
    filetime
        .and_then(datable_filetime)
        .and_then(filetime_to_datetime)
        .map(|t| t.to_string())
}

/// The `(mac, name)` a finding is about.
fn ids(f: &BluetoothFinding) -> (&str, &str) {
    match f {
        BluetoothFinding::PairedDevice { mac, name, .. }
        | BluetoothFinding::LinkKeyStored { mac, name } => (mac, name),
    }
}

/// `" (name)"` when the friendly name is non-empty, else `""` — for embedding in a note.
fn name_suffix(name: &str) -> String {
    if name.is_empty() {
        String::new()
    } else {
        format!(" ({name})")
    }
}

impl Observation for BluetoothFinding {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            BluetoothFinding::PairedDevice { .. } => Severity::Info,
            BluetoothFinding::LinkKeyStored { .. } => Severity::Low,
        })
    }

    fn category(&self) -> Category {
        match self {
            // A paired device is part of the machine's biography (what it connected to).
            BluetoothFinding::PairedDevice { .. } => Category::History,
            // A recoverable plaintext credential left in the hive.
            BluetoothFinding::LinkKeyStored { .. } => Category::Residue,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            BluetoothFinding::PairedDevice { .. } => "BLUETOOTH-PAIRED-DEVICE",
            BluetoothFinding::LinkKeyStored { .. } => "BLUETOOTH-LINK-KEY-STORED",
        }
    }

    fn note(&self) -> String {
        match self {
            BluetoothFinding::PairedDevice {
                mac,
                name,
                last_seen,
                last_connected,
                has_link_key,
            } => {
                let seen = last_seen.as_deref().unwrap_or("unknown");
                let conn = last_connected.as_deref().unwrap_or("unknown");
                let key = if *has_link_key {
                    " A plaintext classic link key is stored for this device."
                } else {
                    ""
                };
                format!(
                    "Paired Bluetooth device {mac}{}. LastSeen {seen}, LastConnected {conn}.{key} \
                     LastConnected/LastSeen may reflect pairing time, not last use — corroborate.",
                    name_suffix(name)
                )
            }
            BluetoothFinding::LinkKeyStored { mac, name } => format!(
                "A plaintext classic Bluetooth link key for device {mac}{} is stored in the SYSTEM \
                 hive and is extractable — consistent with credential material that enables \
                 impersonation of the pairing.",
                name_suffix(name)
            ),
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            BluetoothFinding::PairedDevice { .. } => &[],
            // Unsecured Credentials: Credentials in Registry.
            BluetoothFinding::LinkKeyStored { .. } => &["T1552.002"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (mac, name) = ids(self);
        vec![SubjectRef {
            scheme: "bluetooth".to_string(),
            kind: "device".to_string(),
            id: mac.to_string(),
            label: (!name.is_empty()).then(|| name.to_string()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for a Bluetooth finding under the given scope.
#[must_use]
pub fn to_finding(finding: &BluetoothFinding, scope: impl Into<String>) -> Finding {
    finding.to_finding(Source {
        analyzer: "bluetooth-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;

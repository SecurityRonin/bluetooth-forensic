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

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use winreg_core::key::filetime_to_datetime;

// Re-export the core type that appears in this crate's public API.
pub use bluetooth_core::BluetoothDevice;

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
pub fn audit(_devices: &[BluetoothDevice]) -> Vec<BluetoothFinding> {
    Vec::new() // RED stub
}

/// Render a raw `FILETIME` to a human-readable UTC string, or `None` when absent/undatable.
#[must_use]
pub fn render_time(filetime: Option<u64>) -> Option<String> {
    filetime
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
        String::new() // RED stub
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

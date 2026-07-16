//! `bluetooth4n6` — read a Windows `SYSTEM` hive's MS Bluetooth stack (`BTHPORT`) and print every
//! paired device (MAC, friendly name, LastSeen/LastConnected) plus graded findings.
//!
//! Decoding + analysis live in the `bluetooth_forensic` / `bluetooth_core` libraries; this binary
//! only wires `winreg-core` (open the hive, walk `Services\BTHPORT\Parameters\Devices\{MAC}` across
//! control sets, read each device's `Name` / `LastSeen` / `LastConnected` values, and check the
//! `…\Parameters\Keys` subtree for a stored link key) to [`bluetooth_core::decode_device`] and
//! [`bluetooth_forensic::audit`], then renders the result.
//!
//! Paths follow RegRipper's `bthport.pl` (`keydet89/RegRipper3.0`): the device subkeys under
//! `services\BTHPORT\Parameters\Devices` (L56), the subkey name as the device MAC (L66), and the
//! `Name` / `LastSeen` / `LastConnected` values (L72/L77/L82).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Cursor;
use std::process::ExitCode;

use bluetooth_core::{decode_device, parse_mac, BluetoothDevice};
use bluetooth_forensic::{audit, render_time, BluetoothFinding};
use forensicnomicon::report::Observation;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// Control sets to walk. `bthport.pl` resolves the current set via `Select\Current`; walking both
/// numbered sets is equivalent and robust (a hive populates one or both).
const CONTROL_SETS: &[&str] = &["ControlSet001", "ControlSet002"];

/// One paired device plus the byte length of its stored link key (if any), for reporting.
struct DeviceRecord {
    device: BluetoothDevice,
    link_key_len: Option<usize>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(hive_path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: bluetooth4n6 <SYSTEM-hive>");
        return ExitCode::from(2);
    };

    match run(hive_path) {
        Ok(records) => {
            print_report(&records);
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("bluetooth4n6: {hive_path}: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Open the hive and collect every paired Bluetooth device across control sets.
fn run(hive_path: &str) -> Result<Vec<DeviceRecord>, String> {
    let hive = Hive::from_path(std::path::Path::new(hive_path)).map_err(|e| format!("{e}"))?;
    collect_devices(&hive)
}

/// Walk each control set's `BTHPORT\Parameters\Devices` and, keyed by device MAC, assemble a record;
/// link-key presence/length comes from the sibling `Keys` subtree.
fn collect_devices(hive: &Hive<Cursor<Vec<u8>>>) -> Result<Vec<DeviceRecord>, String> {
    let mut records = Vec::new();
    for cs in CONTROL_SETS {
        let devices_path = format!(r"{cs}\Services\BTHPORT\Parameters\Devices");
        let Some(devices) = hive.open_key(&devices_path).map_err(|e| format!("{e}"))? else {
            continue;
        };
        let link_keys = collect_link_keys(hive, cs)?;
        for dev_key in devices.subkeys().map_err(|e| format!("{e}"))? {
            let subkey_name = dev_key.name();
            let Some(mac) = parse_mac(&subkey_name) else {
                continue; // not a device MAC subkey
            };
            let name = read_name_value(&dev_key)?;
            let last_seen = read_raw(&dev_key, "LastSeen")?;
            let last_connected = read_raw(&dev_key, "LastConnected")?;
            let link_key_len = link_keys.get(&mac).copied();
            let Some(device) = decode_device(
                &subkey_name,
                name.as_ref().map(|(d, sz)| (d.as_slice(), *sz)),
                last_seen.as_deref(),
                last_connected.as_deref(),
                link_key_len.is_some(),
            ) else {
                continue;
            };
            records.push(DeviceRecord {
                device,
                link_key_len,
            });
        }
    }
    Ok(records)
}

/// Read the `Name` value's `(bytes, is_reg_sz)`, or `None` when absent. `is_reg_sz` is true for
/// `REG_SZ`/`REG_EXPAND_SZ` (UTF-16LE), false for `REG_BINARY` (ASCII with trailing NUL).
fn read_name_value(
    key: &Key<'_, Hive<Cursor<Vec<u8>>>>,
) -> Result<Option<(Vec<u8>, bool)>, String> {
    let Some(value) = key.value("Name").map_err(|e| format!("{e}"))? else {
        return Ok(None);
    };
    let is_reg_sz = matches!(value.data_type().name(), "REG_SZ" | "REG_EXPAND_SZ");
    let data = value.raw_data().map_err(|e| format!("{e}"))?;
    Ok(Some((data, is_reg_sz)))
}

/// Read a value's raw bytes by name, or `None` when the value is absent.
fn read_raw(key: &Key<'_, Hive<Cursor<Vec<u8>>>>, name: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = key.value(name).map_err(|e| format!("{e}"))? else {
        return Ok(None);
    };
    Ok(Some(value.raw_data().map_err(|e| format!("{e}"))?))
}

/// Collect the device MACs that have a stored link key under `{cs}\…\BTHPORT\Parameters\Keys`,
/// mapped to the key's byte length. Under each adapter subkey the link keys are `REG_BINARY`
/// values named by the remote device MAC (a plaintext classic link key is 16 bytes). The key
/// bytes themselves are never read or retained — only the MAC and the length.
fn collect_link_keys(
    hive: &Hive<Cursor<Vec<u8>>>,
    cs: &str,
) -> Result<BTreeMap<String, usize>, String> {
    let mut out = BTreeMap::new();
    let keys_path = format!(r"{cs}\Services\BTHPORT\Parameters\Keys");
    let Some(keys) = hive.open_key(&keys_path).map_err(|e| format!("{e}"))? else {
        return Ok(out);
    };
    for adapter in keys.subkeys().map_err(|e| format!("{e}"))? {
        for value in adapter.values().map_err(|e| format!("{e}"))? {
            if let Some(mac) = parse_mac(&value.name()) {
                out.insert(mac, value.data_size() as usize);
            }
        }
    }
    Ok(out)
}

fn print_report(records: &[DeviceRecord]) {
    let with_key = records.iter().filter(|r| r.link_key_len.is_some()).count();
    println!(
        "Bluetooth: {} paired device(s), {with_key} with a stored link key",
        records.len()
    );

    for r in records {
        let d = &r.device;
        let name = if d.name.is_empty() {
            "(no name)".to_string()
        } else {
            format!("\"{}\"", d.name)
        };
        let seen = render_time(d.last_seen_filetime).unwrap_or_else(|| "-".to_string());
        let conn = render_time(d.last_connected_filetime).unwrap_or_else(|| "-".to_string());
        let key = match r.link_key_len {
            Some(len) => format!("link-key: present ({len} bytes)"),
            None => "link-key: none".to_string(),
        };
        println!("  {}  {name}", d.mac);
        println!("    LastSeen: {seen}   LastConnected: {conn}   {key}");
    }

    let devices: Vec<BluetoothDevice> = records.iter().map(|r| r.device.clone()).collect();
    let findings = audit(&devices);
    let graded = findings
        .iter()
        .filter(|f| matches!(f, BluetoothFinding::LinkKeyStored { .. }))
        .count();
    println!("\nFindings ({}, {graded} graded):", findings.len());
    for f in &findings {
        let sev = f
            .severity()
            .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
        println!("  [{sev}] {}", f.code());
        println!("    {}", f.note());
    }
}

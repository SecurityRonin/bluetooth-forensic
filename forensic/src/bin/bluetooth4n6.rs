//! `bluetooth4n6` — read a Windows `SYSTEM` hive's MS Bluetooth stack (`BTHPORT`) and print every
//! paired device (MAC, friendly name, LastSeen/LastConnected) plus graded findings.
//!
//! Decoding, analysis, and the hive walk all live in the `bluetooth_forensic` / `bluetooth_core`
//! libraries; this binary only opens the `SYSTEM` hive with `winreg-core`, hands it to the
//! [`bluetooth_forensic::devices_from_hive`] seam, and renders the decoded devices plus
//! [`bluetooth_forensic::audit`] findings.
//!
//! The walk itself (control sets, `Services\BTHPORT\Parameters\Devices\{MAC}`, the `Keys` link-key
//! cross-reference) follows RegRipper's `bthport.pl` (`keydet89/RegRipper3.0`) and is documented on
//! the seam.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use bluetooth_forensic::{
    audit, devices_from_hive, render_time, BluetoothDevice, BluetoothFinding,
};
use forensicnomicon::report::Observation;
use winreg_core::hive::Hive;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(hive_path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: bluetooth4n6 <SYSTEM-hive>");
        return ExitCode::from(2);
    };

    match run(hive_path) {
        Ok(devices) => {
            print_report(&devices);
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("bluetooth4n6: {hive_path}: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Open the hive and collect every paired Bluetooth device across control sets via the library seam.
fn run(hive_path: &str) -> Result<Vec<BluetoothDevice>, String> {
    let hive = Hive::from_path(std::path::Path::new(hive_path)).map_err(|e| format!("{e}"))?;
    Ok(devices_from_hive(&hive))
}

fn print_report(devices: &[BluetoothDevice]) {
    let with_key = devices.iter().filter(|d| d.has_link_key).count();
    println!(
        "Bluetooth: {} paired device(s), {with_key} with a stored link key",
        devices.len()
    );

    for d in devices {
        let name = if d.name.is_empty() {
            "(no name)".to_string()
        } else {
            format!("\"{}\"", d.name)
        };
        let seen = render_time(d.last_seen_filetime).unwrap_or_else(|| "-".to_string());
        let conn = render_time(d.last_connected_filetime).unwrap_or_else(|| "-".to_string());
        let key = if d.has_link_key {
            "link-key: present"
        } else {
            "link-key: none"
        };
        println!("  {}  {name}", d.mac);
        println!("    LastSeen: {seen}   LastConnected: {conn}   {key}");
    }

    let findings = audit(devices);
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

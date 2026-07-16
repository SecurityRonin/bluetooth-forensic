//! Fuzz target: run the analyzer over an arbitrary device built from fuzz bytes.
//! Invariant: `audit`, `render_time`, and the `Observation` note/subject rendering never panic —
//! including on non-UTF-8-derived names, absent/undatable FILETIMEs, and either link-key state.
#![no_main]
use bluetooth_forensic::{audit, render_time, BluetoothDevice};
use forensicnomicon::report::Observation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let name = String::from_utf8_lossy(data).into_owned();
    let ft = data
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes);
    let _ = render_time(ft);

    let device = BluetoothDevice {
        mac: name.clone(),
        name,
        last_seen_filetime: ft,
        last_connected_filetime: ft,
        has_link_key: data.first().is_some_and(|b| b & 1 == 0),
    };
    for f in audit(std::slice::from_ref(&device)) {
        // Exercise every Observation projection the report layer uses.
        let _ = f.note();
        let _ = f.subjects();
        let _ = f.severity();
        let _ = f.mitre();
    }
});

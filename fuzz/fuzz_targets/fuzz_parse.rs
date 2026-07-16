//! Fuzz target: feed arbitrary bytes to every pure Bluetooth decoder.
//! Invariant: none of `parse_mac`, `decode_name`, `decode_filetime`, or `decode_device` panics on
//! any input — a malformed MAC yields `None`, odd-length `Name` bytes drop the lone trailing byte,
//! and the 8-byte FILETIME read is bounds-checked.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the input into a subkey-name prefix and the value bytes, so the
    // MAC parser and the value decoders are exercised on related-but-distinct slices.
    let split = data
        .first()
        .map_or(0, |b| (*b as usize) % (data.len().max(1)));
    let name = String::from_utf8_lossy(&data[..split.min(data.len())]);

    let _ = bluetooth_core::parse_mac(&name);
    let _ = bluetooth_core::decode_name(data, true);
    let _ = bluetooth_core::decode_name(data, false);
    let _ = bluetooth_core::decode_filetime(data);
    let _ = bluetooth_core::decode_device(
        &name,
        Some((data, data.first().is_some_and(|b| b & 1 == 0))),
        Some(data),
        Some(data),
        data.first().is_some_and(|b| b & 2 == 0),
    );
});

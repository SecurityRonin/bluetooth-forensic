# bluetooth-forensic

Read a Windows **`SYSTEM`** hive — the MS Bluetooth stack's record of *which devices this machine
paired with, and when* — on any OS.

When a Windows host pairs with a Bluetooth device, it records the device under
`ControlSet00N\Services\BTHPORT\Parameters\Devices\{deviceMAC}`: the subkey **name is the device
MAC** (12 hex, no separators), with a friendly `Name` and `LastSeen` / `LastConnected` `FILETIME`s.
A plaintext classic link key, when present, lives under `…\Parameters\Keys\{adapterMAC}\{deviceMAC}`.

`bluetooth-forensic-core` (imports as `bluetooth_core`) is the pure decoder (`parse_mac`, `decode_name`, `decode_filetime`,
`decode_device`); `bluetooth-forensic` walks the hive's control sets, reports each paired device as
evidence, flags a stored extractable link key, and ships the **`bluetooth4n6`** CLI.

```console
$ cargo install bluetooth-forensic
$ bluetooth4n6 /path/to/SYSTEM
```

> Bluetooth pairing records establish that a device was **paired** with this machine — the
> timestamps may reflect *pairing* time, not last use. Findings are observations ("consistent
> with …"), never verdicts.

See the [project README](https://github.com/SecurityRonin/bluetooth-forensic) for full usage and the
findings table, and [Validation](validation.md) for how correctness is established.

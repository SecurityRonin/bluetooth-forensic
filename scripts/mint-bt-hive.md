# Minting a real `SYSTEM` hive with Bluetooth pairings (tier-1 positive fixture)

The whole-hive walk (`devices_from_hive`) is cross-checked against an independent REGF parser
(regipy) on a **synthetic** hive today — tier-2. The remaining **tier-1 positive** needs a *real*
`SYSTEM` hive whose `BTHPORT\Parameters\Devices` actually contains paired-device subkeys. Public
class-scenario and VM images almost never carry Bluetooth pairings (the 2018 Digital Corpora *Lone
Wolf* SYSTEM hive, for instance, has the full BTHPORT stack and a host radio adapter but **zero**
paired devices), so the reliable path is to **mint one on a live Windows box**. This is an operator
step — it cannot be done on this macOS host or on a cloud VM (no Bluetooth radio).

## What you need

- A physical Windows 10 or 11 machine with a working **classic (BR/EDR) Bluetooth** adapter.
- At least one classic Bluetooth device to pair — headphones, a mouse, a keyboard, a speaker. (BLE-only
  peripherals may not populate `BTHPORT\Parameters\Devices`; classic pairing is what writes the
  device subkey + `Name` + `LastSeen`/`LastConnected`, and a link key under `Parameters\Keys`.)
- Local Administrator rights (reading the live `SYSTEM` hive and its `Keys` subtree needs elevation).

## Procedure

1. **Pair one or more classic devices.** Settings → *Bluetooth & devices* → *Add device* →
   *Bluetooth*, and complete pairing. Connect and use each device briefly so `LastConnected` is
   written. Note each device's MAC and friendly name for later reconciliation.

2. **Confirm the pairing landed in the registry.** In an elevated PowerShell:

   ```powershell
   Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
   ```

   Each paired device is a subkey named by its 12-hex MAC (no separators). You should see one subkey
   per device, each with `Name`, `LastSeen`, and `LastConnected` values.

3. **Export the `SYSTEM` hive.** `reg save` writes a consistent copy of the live hive (this is a
   proper hive image, not a `.reg` text export):

   ```powershell
   reg save HKLM\SYSTEM C:\evidence\SYSTEM /y
   ```

   `reg save` produces a single self-contained hive; the live `.LOG1`/`.LOG2` transaction logs are
   already folded in, so you do **not** need them. (If you instead grab the raw
   `C:\Windows\System32\config\SYSTEM` + its LOG files from a dead box, apply the logs first — e.g.
   `regipy`'s `apply_transaction_logs` — before using it, or recent pairings may be missing.)

4. **Move the hive off the Windows box** to wherever you run the tests (scp/USB/share). Keep it out
   of version control — it is a real hive and may carry a plaintext link key; treat it as evidence.

## Verify + reconcile (the oracle)

`scripts/bthport_oracle.py` is the independent oracle: it dumps the pairings with **regipy** (a
third-party REGF parser sharing no code with this crate) as JSON.

```bash
python3 -m pip install regipy          # once
python3 scripts/bthport_oracle.py /path/to/SYSTEM
# → [{"mac": "AA:BB:...", "name": "...", "last_seen": <u64|null>,
#     "last_connected": <u64|null>, "has_link_key": true|false}, ...]
```

Sanity-check that the MACs, names, and link-key flags match the devices you paired in step 1. Then
run the crate's differential against the same hive — it reconciles `devices_from_hive` field-by-field
with the oracle:

```bash
BLUETOOTH_TEST_SYSTEM_HIVE=/path/to/SYSTEM \
  cargo test -p bluetooth-forensic --test hive_seam_oracle real_hive_reconciles_with_regipy_oracle
```

A green run over a real hive is the tier-1 positive. The CLI-level count reconciliation against
RegRipper's `bthport.pl` (the documented format authority, ADR-0003) is the complementary check:

```bash
BLUETOOTH_TEST_SYSTEM_HIVE=/path/to/SYSTEM \
  cargo test -p bluetooth-forensic --test system_real
```

## Recording provenance

When a real hive is minted, add its provenance to `core/tests/data/README.md` (source machine, Windows
build, devices paired, sha256 — never the bytes; the hive stays gitignored/off-repo) and note it in
the fleet catalog `ronin-issen/docs/test-data-catalog.md`.

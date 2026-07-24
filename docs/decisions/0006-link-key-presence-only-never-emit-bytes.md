# 6. Record link-key presence and length only — never read or emit the key bytes

Date: 2026-07-24
Status: Accepted

## Context

Under `…\BTHPORT\Parameters\Keys\{adapterMAC}\{deviceMAC}` the MS Bluetooth stack
stores a **plaintext 16-byte classic link key** per paired device. That key is
live credential material: extracting it enables impersonation of the pairing. A
forensic tool that dumped the bytes into its output would spread the credential
into report files, terminals, and logs that carry a far lower protection standard
than the hive itself — turning an analysis run into a credential-exfiltration
step. This is the Secure-by-Design axiom applied to output: the safe behavior must
be structural, not a documented "don't do that."

## Decision

Record only the **presence and length** of the link key, never its bytes.
`BluetoothDevice` carries a `has_link_key: bool` (`core/src/lib.rs`) — not the key
material — and the CLI checks the `Keys` subtree only to set that flag
(`forensic/src/bin/bluetooth4n6.rs`). The graded finding
`BLUETOOTH-LINK-KEY-STORED` states that a key "is stored … and is extractable"
(with its length, e.g. `16 bytes`) as an observation, and never emits the value
(`forensic/src/lib.rs`; README: "records only its presence and length — it never
reads or emits the key bytes").

## Consequences

- The tool's output cannot leak a credential that was better protected inside the
  hive; the safe path is the only path, with no flag to opt into dumping bytes.
- The finding still carries full evidentiary weight — presence, length, device
  identity, and the impersonation consequence (MITRE `T1552.002`) — without the
  material itself.
- An examiner who genuinely needs the key bytes uses a separate,
  deliberately-scoped extraction tool; recovering them is out of scope here.

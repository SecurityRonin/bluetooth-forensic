# 7. Evidence-first findings, no High verdicts, an explicit pairing-time caveat

Date: 2026-07-24
Status: Accepted

## Context

A `BTHPORT` pairing record establishes that a device was **paired** with this
machine. It does not establish what was done with the device, and its `LastSeen` /
`LastConnected` timestamps may reflect *pairing* time rather than last use. The
fleet reporting model (`forensicnomicon::report`) requires findings to be
observations, never legal conclusions, and to carry a severity that honestly
reflects what the artifact proves. Over-grading a pairing record as a High-severity
event would assert a conclusion the evidence cannot support.

## Decision

Emit findings evidence-first via `forensicnomicon::report`
(`forensic/src/lib.rs`):

- **Every paired device → an `Info` `BLUETOOTH-PAIRED-DEVICE` finding** stating the
  MAC, friendly name, and `LastSeen` / `LastConnected`, with an explicit caveat
  that those timestamps may reflect pairing time, not last use ("corroborate").
- **A stored plaintext link key → a single `Low` `BLUETOOTH-LINK-KEY-STORED`
  finding** tagged MITRE `T1552.002` (Credentials in Registry), phrased as
  "consistent with credential material that enables impersonation", not a verdict.
- **No High-severity findings.** The hive proves pairing, not use, so nothing here
  grades higher than `Low` (`forensic/src/lib.rs`: "No High-severity verdicts").

## Consequences

- The output separates observed fact (a device was paired) from inference (the key
  is extractable credential material) and never crosses into a legal conclusion —
  the examiner/tribunal concludes.
- Severities stay defensible: an examiner reading a `Low` knows the strongest claim
  the artifact supports, and the pairing-time caveat travels with every device
  record so timestamps are not over-read.
- New signals get new scheme-prefixed codes rather than re-grading a shipped one,
  keeping the codes a stable published contract.

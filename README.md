# I7 — CAN Bus Analyzer

Raw bit-level CAN frame parser, signal decoder, ID whitelist auditor, and a
deterministic frame fuzzer. Offline-safe — fixture logs only, no hardware
required. Standard-library only.

## What the engine genuinely does

- **Raw bit-level parser** — `CANFrame.parse_hex` accepts `ID#DATA` and `ID,DATA`
  lines; `CANHeaderParser` extracts the exact header fields (arbitration ID,
  standard vs extended format, RTR bit, DLC, payload hex) from the raw bytes.
- **Bit-field signal decoder** — extracts signals from payload bits (MSB-first
  motorola byte order) with scale/offset/units against an illustrative CAN
  database (Engine RPM, Vehicle Speed, Door Status, Battery).
- **ID whitelist auditor** — compares every observed arbitration ID against an
  authorized whitelist and reports unknown/unexpected IDs that would be
  red-flagged by a vehicle SOC (known attack vector: spoofing an unknown ID).
- **Deterministic fuzzer** — bitflip / byte / truncate / inflate / swap /
  garbage mutations of real frames with a fixed seed, so results are
  reproducible and offline.
- **Byte-exact serialization** — struct round-trip: 4-byte LE ID + DLC +
  8-byte body + flags byte (extended/remote/error bits), with round-trip tests.
- **Fixture log** — bundled `FIDUCIAL_FIXTURES` (also written via
  `write_fixtures`) for reproducible tests.

## Quick start

```bash
# Offline demo: fixtures, decode, whitelist audit, fuzzer, JSON report, exit 0
python3 firmware/canbus.py --demo

# Parse a CAN log and dump raw header fields
python3 firmware/canbus.py captures/vehicle.log --dump

# Audit IDs against an allowlist
python3 firmware/canbus.py captures/vehicle.log --audit --whitelist 123 1F0 2B0 3E8

# Fuzz frames deterministically
python3 firmware/canbus.py captures/vehicle.log --fuzz --fuzz-iterations 200 --seed 42 --json

# Tests
python3 -m unittest discover -s tests
```

Log format (`ID#DATA` hex):

```
123#0320000000000000
1F0#4800000000000000
```

## CLI

```
python3 firmware/canbus.py [-h] [--demo] [logfile] [--dump] [--audit]
                           [--whitelist ID [ID ...]] [--fuzz]
                           [--fuzz-iterations N] [--seed N] [--json]
                           [--report-dir DIR]
```

- `--demo` — offline fixture demo, exit 0.
- `--json` — write JSON report to `reports/`.
- Frame injection onto a live bus is NOT performed — the fuzzer and auditor
  are analysis-only; physical injection would require explicit hardware setup.

Exit codes: `0` success, non-zero on errors.

## Live Lab Test Plan

Prerequisites: a CAN log from a lab bench you own (e.g. a can-utils
`candump` export), or the bundled fixtures. Do NOT attach to real vehicle
networks without authorization.

1. **Baseline**: `python3 firmware/canbus.py --demo` — confirm RPM=200.0,
   speed=72.0, door driver=1, battery 25.0 V are decoded from fixtures, the
   whitelist audit flags 0x7E0/0x7FF as unknown (expected result), the fuzzer
   mutates 40 frames, round-trip is OK, and the JSON report is written
   (exit 0).
2. **Real log**: capture `candump -l vcan0` output, feed it as a logfile, and
   confirm header fields parse for every frame line.
3. **Audit**: run `--audit` against a whitelist of IDs you canonically expect
   on your lab bench; confirm unknown IDs are enumerated.
4. **Fuzz**: `--fuzz --seed 42` twice — confirm byte-identical mutant sets
   (determinism check for regression).
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 22    |
| Fixture set                | bundled `FIDUCIAL_FIXTURES` |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Wire format                | CAN 2.0A/2.0B raw frames |
| Fuzzer determinism         | fixed seed (default 42) |
| Injection                  | analysis-only (no live bus writes) |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. Only analyze CAN traffic from
vehicles/buses you own or are explicitly authorized to assess. This tool is
analysis-only and never writes to a live bus; attaching injection hardware to
a real vehicle network without authorization is illegal. See `LICENSE` for the
full shield — Authorization, CFAA / computer-crime statutes, Acceptable Use,
Prohibited Use, No Warranty, and Responsible Disclosure.

## License

MIT — full legal shield in `LICENSE`.
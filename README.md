> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# I7 — CAN Bus Security Toolkit

An automotive **CAN bus security** analysis suite: raw bit-level frame parsing,
signal decoding, ID whitelist auditing, and a deterministic fuzzer — fully
offline against fixture logs, no hardware required.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/i7-can-bus)](https://github.com/5h4d0wn1k/i7-can-bus)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/i7-can-bus)](https://github.com/5h4d0wn1k/i7-can-bus)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/i7-can-bus)](https://github.com/5h4d0wn1k/i7-can-bus)

## Why I7

Modern vehicles are networks on wheels, and CAN is their backbone — unauthenticated
by design. I7 is a **CAN bus security** study toolkit for **automotive IoT**:
it parses raw `ID#DATA` frames at bit level, decodes embedded signals
(Engine RPM, Vehicle Speed, Door Status, Battery), audits arbitration IDs
against an allowlist a vehicle SOC would use, and fuzzes frames
deterministically. Everything runs offline on bundled fixtures — analysis only,
never writes to a live bus. Workbench tests require CAN traffic from vehicles
or buses you own or hold authorization to assess.

## Features

- **Raw frame parser** — `CANHeaderParser` extracts arbitration ID, standard/extended format, RTR, DLC, payload
- **Bit-field signal decoder** — MSB-first (motorola) signed/unsigned extraction with scale/offset/units
- **ID whitelist auditor** — flags unknown/unexpected arbitration IDs vs. an authorized allowlist
- **Deterministic fuzzer** — bitflip/byte/truncate/inflate/swap/garbage mutations with fixed seed
- **Byte-exact serialization** — struct round-trip (LE ID + DLC + body + flags) with tests
- **Fixture log** — bundled CAN frames for reproducible, offline demos
- **JSON reports** — under `reports/` (gitignored)

## Quickstart

```bash
# Offline demo: decode, whitelist audit, fuzz, JSON report, exit 0
python3 firmware/canbus.py --demo

# Parse a CAN log and dump raw header fields
python3 firmware/canbus.py captures/vehicle.log --dump

# Audit IDs against an allowlist
python3 firmware/canbus.py captures/vehicle.log --audit --whitelist 123 1F0 2B0 3E8

# Fuzz deterministically
python3 firmware/canbus.py captures/vehicle.log --fuzz --fuzz-iterations 200 --seed 42 --json

# Tests
python3 -m unittest discover -s tests
```

Frame log format: `ID#DATA` hex lines:
```
123#0320000000000000
1F0#4800000000000000
```

## Project structure

- `firmware/canbus.py` — parser, decoder, auditor, fuzzer, CLI
- `tests/` — round-trip, signal decode, audit, and determinism tests
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)
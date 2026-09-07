#!/usr/bin/env python3
"""
I7 - CAN Bus Analyzer
CAN frame parser (raw bit-level header fields), fixture decoding, ID whitelist
auditor, and a frame fuzzer. Offline-safe: no hardware required.
Standard-library only.
"""

import struct
import argparse
import sys
import os
import json
import random
import re


FIDUCIAL_FIXTURES = [
    "000#00",                    # standard 11-bit id 0, DLC 0
    "123#0320000000000000",      # Engine RPM fixture (0x0320 q = 200.0 rpm)
    "1F0#4800000000000000",      # Vehicle speed fixture (0x48 = 72 km/h)
    "2B0#8000000000000000",      # Door status fixture (driver bit set)
    "3E8#48FA000000000000",      # Battery fixture (25.0 V, -36 A)
    "7E0#0201FE0000000000",      # Diagnostic (OBD-ish) frame
    "7DF#020A01FFFFFFFFFF",      # Diagnostic broadcast
    "100#0102030405060708",      # Full 8-byte data
    "0FF#00",
    "5A5#DEADBEEF",              # 11-bit id 0x5A5, 4 bytes
]


def write_fixtures(path):
    with open(path, "w") as f:
        for line in FIDUCIAL_FIXTURES:
            f.write(line + "\n")


CAN_DB = {
    0x123: {"name": "Engine RPM", "fields": [
        {"name": "rpm", "offset": 0, "length": 16, "scale": 0.25,
         "offset_v": 0, "unit": "rpm"},
    ]},
    0x1F0: {"name": "Vehicle Speed", "fields": [
        {"name": "speed", "offset": 0, "length": 8, "scale": 1.0,
         "offset_v": 0, "unit": "km/h"},
    ]},
    0x2B0: {"name": "Door Status", "fields": [
        {"name": "driver", "offset": 0, "length": 1},
        {"name": "passenger", "offset": 1, "length": 1},
        {"name": "rear_left", "offset": 2, "length": 1},
        {"name": "rear_right", "offset": 3, "length": 1},
    ]},
    0x3E8: {"name": "Battery", "fields": [
        {"name": "voltage", "offset": 8, "length": 8, "scale": 0.1,
         "offset_v": 0, "unit": "V"},
        {"name": "current", "offset": 0, "length": 8, "scale": -0.5,
         "offset_v": 0, "unit": "A"},
    ]},
}


class CANFrame:
    """A parsed classic CAN frame."""

    CLASSIC_MAX_DLC = 8

    def __init__(self, arb_id, data, dlc=None, flags=0, extended=False,
                 fd=False, bitrate_switch=False, error_flag=False,
                 remote=False):
        self.arb_id = arb_id
        self.data = data
        self.dlc = dlc if dlc is not None else len(data)
        self.flags = flags
        self.extended = extended
        self.fd = fd
        self.bitrate_switch = bitrate_switch
        self.error_flag = error_flag
        self.remote = remote

    @classmethod
    def parse_hex(cls, line):
        """Parse 'ID#DATA' or 'ID,DATA' hex lines (raw bit-level header)."""
        line = line.strip()
        if not line or line.startswith("#"):
            raise ValueError("Empty comment line")
        if "#" in line:
            arb_s, data_s = line.split("#", 1)
        elif "," in line:
            parts = line.split(",")
            arb_s, data_s = parts[0].strip(), parts[1].strip()
        elif any(c in line for c in "ABCDEFabcdef"):
            # bare hex with no data
            arb_s, data_s = line, "00"
        else:
            raise ValueError("Unknown frame format: %s" % line)
        try:
            arb_id = int(arb_s, 16)
        except ValueError:
            raise ValueError("Bad identifier: %s" % arb_s)
        data = bytes.fromhex(data_s)
        if len(data) > cls.CLASSIC_MAX_DLC:
            raise ValueError("Data too long for classic CAN")
        return cls(arb_id, data)

    def to_bytes(self):
        """Serialize: ID(4, LE, masked 29-bit) + DLC(1) + data(0-8) + flags(1)."""
        id_mask = 0x1FFFFFFF if self.extended else 0x7FF
        head = struct.pack("<IB", self.arb_id & id_mask, self.dlc)
        body = self.data[:8].ljust(8, b"\x00")
        flags = self.flags
        if self.extended:
            flags |= 0x02
        if self.remote:
            flags |= 0x04
        if self.error_flag:
            flags |= 0x80
        return head + body + struct.pack("B", flags)

    @classmethod
    def from_bytes(cls, raw):
        if len(raw) < 14:
            raise ValueError("Frame too short")
        arb_id, dlc = struct.unpack("<IB", raw[:5])
        data = raw[5:5 + min(dlc, 8)]
        flags = raw[13]
        return cls(arb_id, data, dlc=dlc,
                   extended=bool(flags & 0x02),
                   remote=bool(flags & 0x04),
                   error_flag=bool(flags & 0x80))

    @property
    def is_standard(self):
        return self.arb_id <= 0x7FF

    def __repr__(self):
        return "CANFrame(id=0x%X, dlc=%d, data=%s)" % (
            self.arb_id, self.dlc, self.data.hex().upper())


class CANHeaderParser:
    """Raw bit-level CAN header field parser (classic 2.0A/2.0B)."""

    def parse(self, frame):
        ident = frame.arb_id
        if not (0 <= ident <= 0x1FFFFFFF):
            raise ValueError("Identifier out of range")
        sid = ident & 0x7FF
        if frame.extended:
            eid = ident & 0x1FFFFFFF
            return {
                "format": "extended (CAN 2.0B)",
                "arbitration_id": eid,
                "sid": sid,
                "eid": eid >> 11,
                "rtr": frame.remote,
                "idr": 0,
                "dlc": frame.dlc,
                "r": 0,
                "data_length": len(frame.data),
                "payload_hex": frame.data.hex().upper(),
            }
        return {
            "format": "standard (CAN 2.0A)",
            "arbitration_id": sid,
            "sid": sid,
            "eid": 0,
            "rtr": frame.remote,
            "idr": 0,
            "dlc": frame.dlc,
            "r": 0,
            "data_length": len(frame.data),
            "payload_hex": frame.data.hex().upper(),
        }


def _read_bits(data, bit_offset, length):
    value = 0
    for i in range(length):
        bit = bit_offset + i
        byte_idx = bit // 8
        bit_in_byte = 7 - (bit % 8)
        if byte_idx < len(data):
            bitval = (data[byte_idx] >> bit_in_byte) & 1
        else:
            bitval = 0
        value = (value << 1) | bitval
    return value


class CANDecoder:
    def __init__(self, db=CAN_DB):
        self.db = db

    def decode(self, frame):
        spec = self.db.get(frame.arb_id)
        if not spec:
            return None
        result = {"name": spec["name"], "signals": []}
        for f in spec["fields"]:
            val = self._extract(frame.data, f)
            result["signals"].append({**f, "value": val})
        return result

    def _extract(self, data, f):
        offset = f["offset"]
        length = f["length"]
        raw = _read_bits(data, offset, length)
        scale = f.get("scale", 1.0)
        off = f.get("offset_v", 0)
        return raw * scale + off


class IDWhitelistAuditor:
    """Compare observed IDs against an authorized whitelist."""

    DEFAULT_WHITELIST = sorted(CAN_DB.keys())

    def __init__(self, whitelist=None):
        self.whitelist = set(whitelist if whitelist is not None
                             else self.DEFAULT_WHITELIST)

    def audit(self, frames):
        observed = set(f.arb_id for f in frames)
        unknown = sorted(observed - self.whitelist)
        authorized = sorted(observed & self.whitelist)
        return {
            "observed": sorted(observed),
            "authorized_count": len(authorized),
            "unknown_count": len(unknown),
            "unknown_ids": unknown,
            "violations": len(unknown) > 0,
        }


class CANFuzzer:
    mutation_positions = list(range(8))

    def __init__(self, seed=42):
        self.rng = random.Random(seed)

    def mutate(self, frame, iterations=100):
        mutated = []
        for _ in range(iterations):
            m = CANFrame(frame.arb_id, bytearray(frame.data), dlc=frame.dlc,
                         extended=frame.extended, remote=frame.remote)
            mode = self.rng.choice(["bitflip", "byte", "truncate", "inflate",
                                    "swap", "garbage"])
            if mode == "bitflip" and m.data:
                b = self.rng.randrange(len(m.data))
                bit = 1 << self.rng.randrange(8)
                m.data[b] ^= bit
            elif mode == "byte" and m.data:
                m.data[self.rng.randrange(len(m.data))] = \
                    self.rng.randrange(256)
            elif mode == "truncate" and m.data:
                m.data = m.data[:self.rng.randrange(len(m.data))]
            elif mode == "inflate" and len(m.data) < 8:
                m.data = bytes(m.data) + bytes([self.rng.randrange(256)])
            elif mode == "swap" and len(m.data) >= 2:
                a = self.rng.randrange(len(m.data))
                b = self.rng.randrange(len(m.data))
                d = list(m.data)
                d[a], d[b] = d[b], d[a]
                m.data = bytes(d)
            elif mode == "garbage":
                num = self.rng.randrange(9)
                m.data = bytes([self.rng.randrange(256) for _ in range(num)])
            if isinstance(m.data, bytearray):
                m.data = bytes(m.data)
            m.dlc = len(m.data)
            mutated.append(m)
        return mutated

    def fuzz(self, frames, iterations=100):
        out = []
        for f in frames:
            out.extend(self.mutate(f, iterations))
        return out


def dump_can_protocol(frames):
    parser = CANHeaderParser()
    header = []
    for f in frames:
        header.append(parser.parse(f))
    return header


def parse_log_file(path):
    frames = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            try:
                frames.append(CANFrame.parse_hex(line))
            except ValueError:
                continue
    return frames


def demo_samples():
    return [
        CANFrame(0x123, bytes.fromhex("0320000000000000")),
        CANFrame(0x1F0, bytes.fromhex("4800000000000000")),
        CANFrame(0x2B0, bytes.fromhex("8000000000000000")),
        CANFrame(0x3E8, bytes.fromhex("48FA000000000000")),
        CANFrame(0x7E0, bytes.fromhex("0201FE0000000000")),
        CANFrame(0x7FF, bytes.fromhex("DEADBEEF")),
    ]


def report(frame, decoder, parser):
    lines = []
    dec = decoder.decode(frame)
    parsed = parser.parse(frame)
    lines.append("Frame: id=0x%X dlc=%d data=%s" %
                 (frame.arb_id, frame.dlc, frame.data.hex().upper()))
    lines.append("  format=%s rtr=%s" % (parsed["format"],
                                          "yes" if parsed["rtr"] else "no"))
    if dec:
        lines.append("  -> %s" % dec["name"])
        for s in dec["signals"]:
            unit = s.get("unit", "")
            lines.append("     %-12s = %s %s" % (s["name"], s["value"], unit))
    else:
        lines.append("  -> unknown ID")
    return "\n".join(lines)


def run_demo(report_dir="reports"):
    print("=== I7 - CAN Bus Analyzer (Offline Demo) ===")
    results = {}

    decoder = CANDecoder()
    parser = CANHeaderParser()

    print("\n-- Fixture frames --")
    frames = demo_samples()
    results["fixture_count"] = len(frames)
    for f in frames:
        print(report(f, decoder, parser))
        print()

    header_fields = dump_can_protocol(frames)
    results["header_fields"] = header_fields
    print("-- Raw header fields (sample) --")
    for hf in header_fields[:3]:
        print("  id=0x%X %s dlc=%d payload=%s" % (
            hf["arbitration_id"], hf["format"], hf["dlc"], hf["payload_hex"]))

    print("\n-- ID whitelist auditor --")
    auditor = IDWhitelistAuditor(whitelist=[0x123, 0x1F0, 0x2B0, 0x3E8])
    audit = auditor.audit(frames)
    print("  observed=%s" % [hex(i) for i in audit["observed"]])
    print("  unknown_ids=%s" % [hex(i) for i in audit["unknown_ids"]])
    print("  unknown_count=%d" % audit["unknown_count"])
    results["audit"] = audit

    print("\n-- Fuzzer (deterministic, seed=42) --")
    fuzzer = CANFuzzer(seed=42)
    seed_frame = frames[0]
    mutants = fuzzer.mutate(seed_frame, iterations=40)
    print("  mutated %d frames from id=0x%X" % (len(mutants), seed_frame.arb_id))
    parseable = 0
    for m in mutants:
        try:
            parser.parse(m)
            parseable += 1
        except ValueError:
            pass
    print("  parseable after mutation: %d/%d" % (parseable, len(mutants)))
    results["fuzz"] = {"mutants": len(mutants), "parseable": parseable,
                       "mutations_count": 40}

    print("\n-- Byte-serialization round trip --")
    rt_ok = True
    for f in frames[:3]:
        raw = f.to_bytes()
        back = CANFrame.from_bytes(raw)
        if back.arb_id != f.arb_id or back.data != f.data:
            rt_ok = False
    print("  round-trip %s" % ("OK" if rt_ok else "MISMATCH"))
    results["round_trip"] = rt_ok

    os.makedirs(report_dir, exist_ok=True)
    rpath = os.path.join(report_dir, "i7_demo_report.json")
    with open(rpath, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\n[+] Report: %s" % rpath)
    print("[+] Demo complete - exit 0")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="I7 - CAN Bus Analyzer (educational, authorized use only)",
        epilog="Example: python3 canbus.py fixtures --audit --fuzz",
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo with fixture frames")
    parser.add_argument("logfile", nargs="?", default=None,
                        help="Path to CAN hex log (ID#DATA lines)")
    parser.add_argument("--dump", action="store_true",
                        help="Dump raw bit-level header fields for all frames")
    parser.add_argument("--audit", action="store_true",
                        help="Run ID whitelist audit")
    parser.add_argument("--whitelist", nargs="+", metavar="ID",
                        help="Authorized IDs (hex), e.g. 123 1F0")
    parser.add_argument("--fuzz", action="store_true",
                        help="Fuzz frames (deterministic seed=42)")
    parser.add_argument("--fuzz-iterations", type=int, default=100,
                        help="Mutations per frame (default 100)")
    parser.add_argument("--seed", type=int, default=42,
                        help="RNG seed for fuzzer (default 42)")
    parser.add_argument("--json", action="store_true",
                        help="Write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports",
                        help="Report output directory (default reports/)")
    args = parser.parse_args()

    if args.demo:
        sys.exit(run_demo(args.report_dir))

    if args.logfile:
        frames = parse_log_file(args.logfile)
    else:
        frames = demo_samples()

    decoder = CANDecoder()
    parser = CANHeaderParser()
    results = {"frames": []}

    print("=== I7 - CAN Bus Analyzer ===")
    print("-- Parsed frames --")
    for f in frames:
        print(report(f, decoder, parser))
        print()

    if args.dump:
        print("-- Raw header fields --")
        for f in frames:
            hf = parser.parse(f)
            print("  id=0x%X %s dlc=%d rtr=%s payload=%s" % (
                hf["arbitration_id"], hf["format"], hf["dlc"],
                hf["rtr"], hf["payload_hex"]))
        results["header_fields"] = [parser.parse(f) for f in frames]

    if args.audit:
        whitelist = None
        if args.whitelist:
            whitelist = [int(x, 16) for x in args.whitelist]
        auditor = IDWhitelistAuditor(whitelist)
        audit = auditor.audit(frames)
        print("-- ID whitelist audit --")
        print("  observed: %s" % [hex(i) for i in audit["observed"]])
        print("  authorized: %d, unknown: %d" % (
            audit["authorized_count"], audit["unknown_count"]))
        for u in audit["unknown_ids"]:
            print("  [!] UNKNOWN ID 0x%X" % u)
        if audit["violations"]:
            print("  [!] AUDIT FAILED: %d unauthorized IDs observed" %
                  audit["unknown_count"])
        results["audit"] = audit

    if args.fuzz:
        fuzzer = CANFuzzer(seed=args.seed)
        mutants = fuzzer.fuzz(frames, args.fuzz_iterations)
        ok = 0
        for m in mutants:
            try:
                parser.parse(m)
                ok += 1
            except ValueError:
                pass
        print("-- Fuzz (seed=%d, %d/frame) --" % (args.seed, args.fuzz_iterations))
        print("  generated %d mutants, %d parseable" % (len(mutants), ok))
        results["fuzz"] = {"mutants": len(mutants),
                           "parseable": ok,
                           "mutations_count": args.fuzz_iterations}

    if args.json:
        os.makedirs(args.report_dir, exist_ok=True)
        rpath = os.path.join(args.report_dir, "i7_report.json")
        with open(rpath, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print("\n[+] Report: %s" % rpath)

    sys.exit(0)


if __name__ == "__main__":
    main()
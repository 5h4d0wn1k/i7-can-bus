#!/usr/bin/env python3
"""I7 - CAN Bus Analyzer

CAN frame parsing, message decoding, injection simulation.
Uses struct, and optionally the python-can `can` module.
"""

import struct
import sys
import random

try:
    import can  # noqa: F401 - optional python-can interface
    HAVE_CAN = True
except ImportError:
    HAVE_CAN = False

# Minimal illustrative CAN database (ID -> description + fields)
CAN_DB = {
    0x123: {"name": "Engine RPM", "fields": [
        {"name": "rpm", "offset": 0, "length": 16, "scale": 0.25, "offset_v": 0, "unit": "rpm"},
    ]},
    0x1F0: {"name": "Vehicle Speed", "fields": [
        {"name": "speed", "offset": 0, "length": 8, "scale": 1.0, "offset_v": 0, "unit": "km/h"},
    ]},
    0x2B0: {"name": "Door Status", "fields": [
        {"name": "driver", "offset": 0, "length": 1},
        {"name": "passenger", "offset": 1, "length": 1},
        {"name": "rear_left", "offset": 2, "length": 1},
        {"name": "rear_right", "offset": 3, "length": 1},
    ]},
    0x3E8: {"name": "Battery", "fields": [
        {"name": "voltage", "offset": 8, "length": 8, "scale": 0.1, "offset_v": 0, "unit": "V"},
        {"name": "current", "offset": 0, "length": 8, "scale": -0.5, "offset_v": 0, "unit": "A"},
    ]},
}


class CANFrame:
    def __init__(self, arb_id, data, dlc=None, flags=0):
        self.arb_id = arb_id
        self.data = data
        self.dlc = dlc if dlc is not None else len(data)
        self.flags = flags

    @classmethod
    def parse_hex(cls, line):
        """Parse a line of hex e.g. '123#DEADBEEF' or csv."""
        line = line.strip()
        if "#" in line:
            arb_s, data_s = line.split("#", 1)
            arb_id = int(arb_s, 16)
            data = bytes.fromhex(data_s)
            return cls(arb_id, data)
        elif "," in line:
            parts = line.split(",")
            arb_id = int(parts[0].strip(), 16)
            data = bytes.fromhex(parts[1].strip())
            return cls(arb_id, data)
        else:
            raise ValueError("Unknown frame format")

    def to_bytes(self):
        # CAN frame serialized: ID(4) + DLC(1) + data(0-8)
        return struct.pack("<IB", self.arb_id & 0x1FFFFFFF, self.dlc) + \
            self.data[:8].ljust(8, b"\x00")

    def __repr__(self):
        return "CANFrame(id=0x%X, dlc=%d, data=%s)" % (
            self.arb_id, self.dlc, self.data.hex().upper())


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


def _read_bits(data, bit_offset, length):
    """Extract an integer from data by physical bit offset/length (big-endian)."""
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


class CANInjector:
    """Simulated injection — requires real hardware/socket to be live."""

    def __init__(self, interface="vcan0"):
        self.interface = interface
        self.bus = None
        if HAVE_CAN:
            try:
                self.bus = can.interface.Bus(channel=interface, bustype="socketcan")
            except Exception:
                self.bus = None

    def inject(self, frame):
        if self.bus:
            msg = can.Message(arbitration_id=frame.arb_id, data=frame.data,
                              is_extended_id=False)
            self.bus.send(msg)
            return True
        # Simulation mode
        print("  [sim] INJECT frame: id=0x%X data=%s via %s"
              % (frame.arb_id, frame.data.hex(), self.interface))
        return True


def parse_log_file(path):
    frames = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                frames.append(CANFrame.parse_hex(line))
            except ValueError:
                continue
    return frames


def demo_samples():
    return [
        CANFrame(0x123, bytes.fromhex("C401000000000000")),
        CANFrame(0x1F0, bytes.fromhex("4800000000000000")),
        CANFrame(0x2B0, bytes.fromhex("0500000000000000")),
        CANFrame(0x3E8, bytes.fromhex("A00F000000000000")),
        CANFrame(0x7FF, bytes.fromhex("DEADBEEF")),
    ]


def report(frame, decoder):
    lines = []
    dec = decoder.decode(frame)
    lines.append("Frame: id=0x%X dlc=%d data=%s" %
                 (frame.arb_id, frame.dlc, frame.data.hex().upper()))
    if dec:
        lines.append("  -> %s" % dec["name"])
        for s in dec["signals"]:
            unit = s.get("unit", "")
            lines.append("     %-12s = %s %s" % (s["name"], s["value"], unit))
    else:
        lines.append("  -> unknown ID")
    return "\n".join(lines)


def main():
    if len(sys.argv) > 1:
        frames = parse_log_file(sys.argv[1])
        if not frames:
            print("No frames parsed from %s" % sys.argv[1])
            return 1
    else:
        print("No log file given; using demo frames.\n")
        frames = demo_samples()

    decoder = CANDecoder()
    injector = CANInjector()

    print("=== I7 - CAN Bus Analyzer ===")
    if HAVE_CAN:
        print("python-can available: %s" % injector.interface)
    else:
        print("python-can not installed; simulation mode active.")

    print("\n-- Parsed frames --")
    for f in frames:
        print(report(f, decoder))
        print()

    print("-- Serialized (struct) representation --")
    for f in frames[:3]:
        raw = f.to_bytes()
        print("  id=0x%X  -> %s" % (f.arb_id, raw.hex()))

    print("\n-- Injection simulation --")
    target = frames[1] if len(frames) > 1 else CANFrame(0x1F0, bytes([0x64] * 8))
    print("Injecting spoofed speed frame:")
    injector.inject(CANFrame(0x1F0, bytes([200]) + b"\x00" * 7))

    return 0


if __name__ == "__main__":
    sys.exit(main())

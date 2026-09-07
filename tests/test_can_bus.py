#!/usr/bin/env python3
"""Deterministic offline tests for I7 - CAN bus analyzer (fixture-based)."""

import json
import os
import struct
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO, "firmware"))

import canbus as i7
from canbus import (
    CANFrame, CANHeaderParser, CANDecoder, IDWhitelistAuditor, CANFuzzer,
    demo_samples, parse_log_file, FIDUCIAL_FIXTURES, write_fixtures,
    run_demo, CAN_DB,
)


class TestFrameParse(unittest.TestCase):
    def test_parse_hash_format(self):
        frame = CANFrame.parse_hex("123#C401000000000000")
        self.assertEqual(frame.arb_id, 0x123)
        self.assertEqual(frame.data[:2], b"\xc4\x01")
        self.assertEqual(frame.dlc, 8)

    def test_parse_empty_data(self):
        frame = CANFrame.parse_hex("000#00")
        self.assertEqual(frame.arb_id, 0)
        self.assertEqual(frame.data, b"\x00")
        self.assertEqual(frame.dlc, 1)

    def test_parse_short_fixture(self):
        frame = CANFrame.parse_hex("5A5#DEADBEEF")
        self.assertEqual(frame.arb_id, 0x5A5)
        self.assertEqual(frame.data, b"\xde\xad\xbe\xef")

    def test_parse_invalid_raises(self):
        with self.assertRaises(ValueError):
            CANFrame.parse_hex("nothex")
        with self.assertRaises(ValueError):
            CANFrame.parse_hex("123#ZZ")

    def test_data_too_long(self):
        with self.assertRaises(ValueError):
            CANFrame.parse_hex("123#010203040506070809")


class TestRawHeaderFields(unittest.TestCase):
    def test_standard_id_bits(self):
        """Standard 11-bit arbitration ID is stored verbatim."""
        frame = CANFrame(0x123, b"\x00")
        parser = CANHeaderParser()
        parsed = parser.parse(frame)
        self.assertEqual(parsed["format"], "standard (CAN 2.0A)")
        self.assertEqual(parsed["arbitration_id"], 0x123)
        self.assertEqual(parsed["sid"], 0x123)
        self.assertEqual(parsed["dlc"], 1)

    def test_extended_format(self):
        frame = CANFrame(0x123, b"\xde\xad", extended=True)
        parsed = CANHeaderParser().parse(frame)
        self.assertEqual(parsed["format"], "extended (CAN 2.0B)")
        self.assertEqual(parsed["arbitration_id"], 0x123)

    def test_dlc_matches_header(self):
        frame = CANFrame(0x7E0, b"\x02\x01\xfe\x00\x00\x00\x00\x00")
        parsed = CANHeaderParser().parse(frame)
        self.assertEqual(parsed["dlc"], 8)
        self.assertEqual(parsed["payload_hex"], "0201FE0000000000")


class TestSignalDecode(unittest.TestCase):
    def test_rpm_fixture(self):
        frame = CANFrame(0x123, bytes.fromhex("0320000000000000"))
        dec = CANDecoder().decode(frame)
        self.assertIsNotNone(dec)
        self.assertEqual(dec["name"], "Engine RPM")
        self.assertAlmostEqual(dec["signals"][0]["value"], 200.0)

    def test_speed_fixture(self):
        frame = CANFrame(0x1F0, bytes.fromhex("4800000000000000"))
        dec = CANDecoder().decode(frame)
        self.assertEqual(dec["signals"][0]["value"], 72.0)

    def test_door_status_bits(self):
        frame = CANFrame(0x2B0, bytes.fromhex("8000000000000000"))
        dec = CANDecoder().decode(frame)
        values = {s["name"]: int(s["value"]) for s in dec["signals"]}
        self.assertEqual(values["driver"], 1)
        self.assertEqual(values["passenger"], 0)
        self.assertEqual(values["rear_left"], 0)
        self.assertEqual(values["rear_right"], 0)

    def test_battery_voltage(self):
        frame = CANFrame(0x3E8, bytes.fromhex("48FA000000000000"))
        dec = CANDecoder().decode(frame)
        signals = {s["name"]: s["value"] for s in dec["signals"]}
        self.assertAlmostEqual(signals["voltage"], 25.0)
        self.assertAlmostEqual(signals["current"], -36.0)


class TestWhitelistAudit(unittest.TestCase):
    def test_all_authorized(self):
        frames = demo_samples()
        auditor = IDWhitelistAuditor(whitelist=[0x123, 0x1F0, 0x2B0, 0x3E8, 0x7E0, 0x7FF])
        audit = auditor.audit(frames)
        self.assertFalse(audit["violations"])
        self.assertEqual(audit["unknown_count"], 0)

    def test_unknown_id_detected(self):
        frames = [CANFrame(0x123, b"\x00"), CANFrame(0x999, b"\xaa")]
        auditor = IDWhitelistAuditor(whitelist=[0x123])
        audit = auditor.audit(frames)
        self.assertTrue(audit["violations"])
        self.assertEqual(audit["unknown_ids"], [0x999])

    def test_default_whitelist_is_db(self):
        self.assertEqual(sorted(IDWhitelistAuditor.DEFAULT_WHITELIST),
                         sorted(CAN_DB.keys()))


class TestFuzzer(unittest.TestCase):
    def test_deterministic_seed(self):
        frame = CANFrame(0x123, bytes.fromhex("C401000000000000"))
        f1 = CANFuzzer(seed=42).mutate(frame, iterations=50)
        f2 = CANFuzzer(seed=42).mutate(frame, iterations=50)
        self.assertEqual([m.data for m in f1], [m.data for m in f2])

    def test_mutants_valid(self):
        frame = CANFrame(0x123, bytes.fromhex("C401000000000000"))
        mutants = CANFuzzer(seed=7).mutate(frame, iterations=200)
        self.assertGreaterEqual(len(mutants), 200)
        for m in mutants:
            self.assertLessEqual(len(m.data), 8)
            self.assertEqual(m.dlc, len(m.data))


class TestSerialization(unittest.TestCase):
    def test_round_trip(self):
        raw_frame = CANFrame.parse_hex("3E8#A00F000000000000")
        raw = raw_frame.to_bytes()
        back = CANFrame.from_bytes(raw)
        self.assertEqual(back.arb_id, raw_frame.arb_id)
        self.assertEqual(back.data, raw_frame.data)
        self.assertEqual(back.dlc, raw_frame.dlc)

    def test_fixture_log_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixtures.log")
            write_fixtures(path)
            frames = parse_log_file(path)
            self.assertEqual(len(frames), len(FIDUCIAL_FIXTURES))


class TestHeaderBits(unittest.TestCase):
    def test_error_flag_bit(self):
        frame = CANFrame(0x123, b"\x00", error_flag=True)
        raw = frame.to_bytes()
        # flags byte is the 14th byte (index 13)
        self.assertEqual(raw[13] & 0x80, 0x80)
        back = CANFrame.from_bytes(raw)
        self.assertTrue(back.error_flag)

    def test_remote_bit(self):
        frame = CANFrame(0x123, b"\x00", remote=True)
        raw = frame.to_bytes()
        self.assertEqual(raw[13] & 0x04, 0x04)
        back = CANFrame.from_bytes(raw)
        self.assertTrue(back.remote)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            rpath = os.path.join(tmp, "reports", "i7_demo_report.json")
            self.assertTrue(os.path.exists(rpath))
            with open(rpath) as f:
                data = json.load(f)
            self.assertGreaterEqual(data["fixture_count"], 1)
            self.assertTrue(data["round_trip"])
            self.assertGreaterEqual(data["fuzz"]["mutants"], 1)


if __name__ == "__main__":
    unittest.main()
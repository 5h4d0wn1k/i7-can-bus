# I7 — CAN Bus Analyzer

Parses, decodes, and simulates CAN bus frames for automotive research.

## Overview

This project analyzes CAN (Controller Area Network) traffic:
- Parses CAN frames from logs or demo data
- Decodes signals against a DBC-like database (RPM, speed, doors, battery)
- Bit-level signal extraction with scale/offset
- Serialized struct representation
- Injection simulation (or real send when python-can + SocketCAN present)

## Features

- **Frame parsing**: `ID#DATA` and CSV formats
- **Signal decoding**: bit-field extraction, scaling, units
- **Database**: illustrative CAN database for common IDs
- **Serialization**: struct-based frame encoding
- **Injection**: python-can SocketCAN or simulation mode
- **Demo mode**: works with no external dependencies

## Install (optional)

```bash
pip install python-can
```

## Usage

```bash
python3 canbus.py                 # demo frames
python3 canbus.py captured.log    # parse a hex log
```

Log format:

```
123#C401000000000000
1F0#4800000000000000
```

## Example Output

```
=== I7 - CAN Bus Analyzer ===
Frame: id=0x123 dlc=8 data=C401000000000000
  -> Engine RPM
     rpm         = 200.0 rpm
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT

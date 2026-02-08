# Cloak: Payload Encoder, Obfuscation, Detection, Reporting, and Decoding Framework

Cloak is a modular framework designed to study how offensive payloads can be encoded and obfuscated to evade detection.  
It provides multiple encoding and obfuscation techniques, simulates detection against signature‑based rules, and generates structured reports showing effectiveness.  
Decoding support is included for reversible transformations.

---

## Features
- **Encoding Module**
  - Base64 / Base32 / Base85
  - XOR (user‑defined key)
  - ROT13 / Hex
- **Obfuscation Module**
  - Random character insertion
  - String splitting and concatenation
  - Escape‑sequence obfuscation
  - Reversible transformations
- **Detection Module**
  - Simulated signature checks (`/bin/sh`, `os.system`, `powershell`, `cmd.exe`)
  - Effectiveness analysis (original vs transformed payloads)
- **Reporting Engine**
  - Generates unique report files per run
  - Includes SHA256 hashes, detection outcomes, and bypass verdicts
- **Decoding Module**
  - Decoders for Base64, XOR, ROT13, Hex, Base32, Base85
  - Decoders for reversible obfuscators (reverse, escape, split)
  - Clear warnings for non‑reversible methods (random insert)

---

## Project Structure
```
Cloak/
├── encoders.py        # Encoding techniques
├── obfuscators.py     # Obfuscation techniques
├── detector.py        # Signature detection + effectiveness
├── decoders.py        # Decoding functions
├── report.py          # Reporting engine
├── main.py            # Driver script
└── results/           # Auto‑generated reports
└── Documentation/
    └── screenshots/
    └── cloak.ppt
    └── cloak doc
    └── cloak flowchart
```

---

## Installation

Clone the repository and install required packages:

```bash
git clone https://github.com/Om-Fulsundar/cloak.git
cd cloak
pip install (requirements)
```

### Requirements
  - `argparse` (standard library)
  - `base64` (standard library)
  - `binascii` (standard library)
  - `hashlib` (standard library)
  - `datetime` (standard library)
  - `pathlib` (standard library)

No external dependencies are required beyond Python’s standard library.

---

## Usage

### Encode a payload
```bash
python3 main.py -p "HelloWorld" -e base64
```

### XOR encode with obfuscation
```bash
python3 main.py -p "import os; os.system('/bin/sh')" -e xor -k 42 -o escape
```

### Decode a payload
```bash
python3 main.py -p "SGVsbG9Xb3JsZA==" -e base64 -d
```

### ROT13 decode
```bash
python3 main.py -p "cbjreshyyr" -e rot13 -d
```

---

## Example Output
```
=== Cloak Execution ===
[ENCODER] XOR
[OBFUSCATOR] ESCAPE
[OUTPUT] \x69\x6d\x70\x6f
[DETECTION] Original: DETECTED
[DETECTION] Transformed: BYPASSED
[EFFECTIVENESS] SUCCESS — Transformation bypassed detection.

--- Report saved to results/report_20260202_010145.txt ---
```
---

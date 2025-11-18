CH341A Automated RAM Dump Utility (Python)

A Python‑based automated memory‑extraction pipeline for firmware & RAM analysis using CH341A hardware programmer.

📌 Overview

This project provides a fully automated Python tool for extracting RAM‑mapped memory regions (via SPI/NOR/NAND flash interfaces) using the CH341A hardware programmer.
The tool is designed for IoT Pentesting, Firmware Analysis, Hardware Security Testing, and Memory Forensics, removing the need for manual programmer operations.

The utility performs:

Chip detection (JEDEC probing)

Memory‑geometry parsing

Safe sector‑wise dumping

CRC32 integrity validation

Auto‑retry logic on failed sectors

Optional differential comparison with previous dumps

Export to multiple forensic formats (BIN/RAW/HEX)

This makes it ideal for security professionals performing:

U‑Boot & environment extraction

Runtime memory analysis

Firmware patch diffing

OTP / Secure‑boot parameter collection

Reverse‑engineering workflows (GHIDRA, Ghidra-FW, Binwalk, Radare2)

✨ Key Features

Fully automated CH341A initialization

Dynamic chip detection via JEDEC

Sector‑based parallel dumping (multi‑threaded)

Memory validation using CRC32 + SHA‑256

Offset‑based partial dump support

Structured JSON logs for forensic chains

Auto‑resume dump if connection drops

📁 Directory Structure
CH341A-Dump-Utility/
│
├── src/
│   ├── ch341_interface.py
│   ├── mem_dump.py
│   ├── validator.py
│   └── utils.py
│
├── dumps/
│   └── sample_dump.bin
│
├── logs/
│   └── dump_report.json
│
├── README.md
└── requirements.txt

⚙️ Requirements

Python 3.8+

CH341A Programmer (Black/Gold Edition)

Linux or Windows

pyusb, crcmod, rich, tqdm

Install dependencies:

pip install -r requirements.txt

🚀 Usage
1. Identify connected memory chip
python3 mem_dump.py --identify

2. Dump full memory
python3 mem_dump.py --dump full --out firmware.bin

3. Dump specific offsets
python3 mem_dump.py --dump partial --start 0x00000 --end 0x1FFFFF --out bootloader_region.bin

4. Validate dump
python3 mem_dump.py --validate firmware.bin

🧪 Validation Logic

Each memory chunk is hashed with CRC32

After dump completion, a SHA‑256 hash tree is generated

If a previous dump exists, differential comparison is performed

Any mismatch triggers automatic re‑read

Final dump is verified sector‑by‑sector

🧬 Architecture Flow
CH341A Programmer
       ↓ USB
Python Driver (pyusb)
       ↓
Memory Chip (SPI/NOR/NAND)
       ↓
Sector Reader → Integrity Validator → Assembler
       ↓
Final Dump (BIN/RAW/HEX)
       ↓
JSON Log + Hash Report

📤 Output Files

*.bin — Raw memory dump

*.hex — Intel HEX formatted

dump_report.json — hashes, timing, chip info

diff_report.json — optional comparison log

🛡️ Disclaimer

This tool is for educational and authorized security testing only.
Always ensure you have permission to extract memory from the target device.

🤝 Contributions

PRs, improvements, and feature suggestions are welcome.

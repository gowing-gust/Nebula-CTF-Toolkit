# 🌌 Nebula CTF Toolkit

**Version 1.0.0** — Python + Java CTF Toolkit

---

## What is Nebula?

Nebula is a dual-engine CTF toolkit built with:
- **Python** — interactive shell, crypto tools, forensics, web exploitation, pwn, OSINT
- **Java** — backend engine, session management, reporting, network scanner, Swing GUI dashboard

---

## Quick Start

```bash
# Make the launcher executable
chmod +x nebula.sh

# Launch Python interactive shell (default)
./nebula.sh

# Launch Java CLI engine
./nebula.sh java

# Launch Java Swing GUI
./nebula.sh gui

# Or run Python directly
python3 python/nebula.py
```

---

## Python Shell Commands

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `web` | Web exploitation module |
| `crypto` | Cryptography module |
| `forensics` | Forensics module |
| `pwn` | Binary exploitation module |
| `osint` | OSINT module |
| `scan <host>` | Quick port scan |
| `fuzz <url>` | Directory fuzzer |
| `sqli <url>` | SQL injection test |
| `xss <url>` | XSS test |
| `encode <type> <data>` | Encode data |
| `decode <type> <data>` | Decode data |
| `hash <algo> <data>` | Hash data |
| `identify <hash>` | Identify hash type |
| `caesar <text>` | Brute-force Caesar cipher |
| `flag <value>` | Save a flag |
| `target <host>` | Add a target |
| `session` | Show session summary |
| `save` | Save session |
| `export` | Export HTML report |

---

## Module Overview

### 🔐 Crypto
- Caesar cipher (encrypt / decrypt / brute-force)
- Vigenère cipher (encrypt / decrypt / crack)
- XOR (single byte / repeating key / brute-force)
- RSA (decrypt / compute private key / factorize)
- Hash tools (compute / identify / crack)
- Encodings: Base64, Hex, ROT-13, Atbash, Morse, Binary, URL
- Auto-decode (tries multiple methods)

### 🌐 Web
- SQL injection testing
- XSS (reflected) testing
- LFI testing
- Directory fuzzing
- HTTP header security analysis
- DNS lookup / subdomain enumeration

### 🔍 Forensics
- File type identification (magic bytes + entropy)
- String extraction
- Hidden data scanner (embedded files, URLs, base64)
- File metadata
- File carving (PNG, JPEG, PDF)
- LSB steganography extraction (requires Pillow)

### 💣 Pwn
- Cyclic pattern generator
- Offset finder from crash value
- Shellcode library (x86 / x64)
- Format string probes
- Pack / unpack integers
- Bad character finder
- NOP sled generator
- ELF binary analysis

### 🕵️ OSINT
- Username search across platforms
- Email permutation generator
- Google dork generator
- Page metadata analysis (emails, socials, server)
- DNS + subdomain enumeration

---

## Java Engine Features

- **Session Manager** — save/load JSON sessions
- **Report Generator** — HTML and Markdown reports
- **Network Engine** — threaded port scanner, HTTP client, DNS
- **Challenge Manager** — track CTF challenges with categories, difficulty, points
- **Scoreboard** — track your score and progress
- **Swing GUI Dashboard** — visual dashboard with Web, Crypto, Session, and Challenges tabs

---

## Requirements

**Python:**
- Python 3.8+
- `pip install Pillow` (optional, for image steganography)

**Java:**
- JDK 11+
- `json-simple` JAR (for JSON parsing in Java engine)

---

## File Structure

```
nebula/
├── nebula.sh          ← launcher script
├── python/
│   └── nebula.py      ← Python engine (all modules)
├── java/
│   └── Nebula.java    ← Java engine + GUI
└── README.md
```

---

## Session Files

Sessions are saved to `~/.nebula/sessions/` as JSON files.

---

*Nebula CTF Toolkit — Built for hackers, by hackers.*

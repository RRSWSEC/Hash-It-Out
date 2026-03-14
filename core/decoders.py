"""
core/decoders.py - All reversible decoders for Hash It Out v3
Base2-Base92, all ROTs, classical ciphers, CTF staples, misc encodings.
Zero external dependencies — Python 3.7+ stdlib only.
"""

import base64
import string
import struct
import io
import quopri
from typing import Optional, List, Tuple


# ══════════════════════════════════════════════════════════════════
#  ROT / Caesar family
# ══════════════════════════════════════════════════════════════════

def rot_n(text: str, n: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + n) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def rot47(text: str) -> str:
    return ''.join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in text
    )

def rot5(text: str) -> str:
    return ''.join(
        chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit() else c
        for c in text
    )

def rot18(text: str) -> str:
    return rot5(rot_n(text, 13))


# ══════════════════════════════════════════════════════════════════
#  BASE ENCODINGS  Base2 → Base92
# ══════════════════════════════════════════════════════════════════

def decode_base2(data: str) -> Optional[bytes]:
    try:
        clean = data.strip().replace(' ', '').replace('\n', '')
        if not all(c in '01' for c in clean) or len(clean) % 8 != 0:
            return None
        return bytes(int(clean[i:i+8], 2) for i in range(0, len(clean), 8))
    except Exception:
        return None

def decode_base8(data: str) -> Optional[bytes]:
    try:
        parts = data.strip().split()
        if not parts:
            return None
        result = bytearray()
        for p in parts:
            val = int(p, 8)
            if val > 255:
                return None
            result.append(val)
        return bytes(result)
    except Exception:
        return None

def decode_base10(data: str) -> Optional[bytes]:
    try:
        parts = data.strip().split()
        if len(parts) < 2:
            return None
        result = bytearray()
        for p in parts:
            val = int(p)
            if val > 255:
                return None
            result.append(val)
        return bytes(result)
    except Exception:
        return None

def decode_base16(data: str) -> Optional[bytes]:
    try:
        return base64.b16decode(data.strip().upper())
    except Exception:
        return None

def decode_base32(data: str) -> Optional[bytes]:
    try:
        padded = data.strip().upper()
        missing = len(padded) % 8
        if missing:
            padded += '=' * (8 - missing)
        return base64.b32decode(padded)
    except Exception:
        return None

def decode_base32hex(data: str) -> Optional[bytes]:
    std    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    exthex = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
    try:
        translated = data.strip().upper().translate(str.maketrans(exthex, std))
        missing = len(translated) % 8
        if missing:
            translated += '=' * (8 - missing)
        return base64.b32decode(translated)
    except Exception:
        return None

def decode_base32_crockford(data: str) -> Optional[bytes]:
    CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    STD_B32   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    try:
        text = data.strip().upper().replace('I','1').replace('L','1').replace('O','0')
        translated = ''.join(STD_B32[CROCKFORD.index(c)] for c in text if c in CROCKFORD)
        missing = len(translated) % 8
        if missing:
            translated += '=' * (8 - missing)
        return base64.b32decode(translated)
    except Exception:
        return None

def decode_base36(data: str) -> Optional[bytes]:
    try:
        num = int(data.strip(), 36)
        result = []
        while num > 0:
            result.append(num & 0xFF)
            num >>= 8
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base45(data: str) -> Optional[bytes]:
    ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
    try:
        text = data.strip()
        res = []
        for i in range(0, len(text), 3):
            chunk = text[i:i+3]
            if len(chunk) == 3:
                c, d, e = [ALPHABET.index(x) for x in chunk]
                n = c + d * 45 + e * 2025
                res.extend(divmod(n, 256))
            elif len(chunk) == 2:
                c, d = [ALPHABET.index(x) for x in chunk]
                res.append(c + d * 45)
        return bytes(res)
    except Exception:
        return None

def decode_base58(data: str) -> Optional[bytes]:
    ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 58 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        for ch in data.strip():
            if ch == ALPHA[0]:
                result.append(0)
            else:
                break
        return bytes(reversed(result))
    except Exception:
        return None

def decode_base58_flickr(data: str) -> Optional[bytes]:
    ALPHA = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 58 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base62(data: str) -> Optional[bytes]:
    ALPHA = string.digits + string.ascii_uppercase + string.ascii_lowercase
    try:
        num = 0
        for ch in data.strip():
            if ch not in ALPHA:
                return None
            num = num * 62 + ALPHA.index(ch)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        return bytes(reversed(result)) if result else None
    except Exception:
        return None

def decode_base64(data: str) -> Optional[bytes]:
    try:
        padded = data.strip()
        missing = len(padded) % 4
        if missing:
            padded += '=' * (4 - missing)
        return base64.b64decode(padded)
    except Exception:
        return None

def decode_base64_url(data: str) -> Optional[bytes]:
    try:
        padded = data.strip().replace('-', '+').replace('_', '/')
        missing = len(padded) % 4
        if missing:
            padded += '=' * (4 - missing)
        return base64.b64decode(padded)
    except Exception:
        return None

def decode_base64_mime(data: str) -> Optional[bytes]:
    try:
        clean = ''.join(data.split())
        missing = len(clean) % 4
        if missing:
            clean += '=' * (4 - missing)
        return base64.b64decode(clean)
    except Exception:
        return None

def decode_base85(data: str) -> Optional[bytes]:
    try:
        return base64.b85decode(data.strip())
    except Exception:
        return None

def decode_ascii85(data: str) -> Optional[bytes]:
    try:
        s = data.strip()
        if s.startswith('<~') and s.endswith('~>'):
            s = s[2:-2]
        return base64.a85decode(s)
    except Exception:
        return None

def decode_z85(data: str) -> Optional[bytes]:
    Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
    try:
        text = data.strip()
        if len(text) % 5 != 0:
            return None
        result = bytearray()
        for i in range(0, len(text), 5):
            val = 0
            for c in text[i:i+5]:
                if c not in Z85:
                    return None
                val = val * 85 + Z85.index(c)
            result.extend(struct.pack('>I', val))
        return bytes(result)
    except Exception:
        return None

def decode_base91(data: str) -> Optional[bytes]:
    TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    try:
        decode_table = {c: i for i, c in enumerate(TABLE)}
        v = -1
        b = 0
        n = 0
        result = bytearray()
        for c in data.strip():
            if c not in decode_table:
                continue
            p = decode_table[c]
            if v < 0:
                v = p
            else:
                v += p * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                v = -1
                while n > 7:
                    result.append(b & 255)
                    b >>= 8
                    n -= 8
        if v > -1:
            result.append((b | v << n) & 255)
        return bytes(result) if result else None
    except Exception:
        return None

def decode_base92(data: str) -> Optional[bytes]:
    try:
        text = data.strip()
        if not text:
            return None
        num = 0
        for ch in text:
            code = ord(ch)
            if code < 35 or code > 126:
                return None
            num = num * 91 + (code - 35)
        result = []
        while num > 0:
            result.append(num & 0xFF)
            num >>= 8
        return bytes(reversed(result)) if result else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  HEX variants
# ══════════════════════════════════════════════════════════════════

def decode_hex(data: str) -> Optional[bytes]:
    try:
        clean = data.strip().replace(' ','').replace('\n','')
        clean = clean.replace('0x','').replace('\\x','').replace(':','')
        if len(clean) % 2 != 0:
            clean = '0' + clean
        return bytes.fromhex(clean)
    except Exception:
        return None

def decode_hex_escaped(data: str) -> Optional[bytes]:
    try:
        if '\\x' not in data and '%' not in data:
            return None
        clean = data.strip().replace('\\x','').replace('%','').replace(' ','')
        return bytes.fromhex(clean)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  URL / HTML
# ══════════════════════════════════════════════════════════════════

def decode_url(data: str) -> Optional[str]:
    try:
        from urllib.parse import unquote
        decoded = unquote(data.strip())
        return decoded if decoded != data.strip() else None
    except Exception:
        return None

def decode_url_double(data: str) -> Optional[str]:
    try:
        from urllib.parse import unquote
        first = unquote(data.strip())
        second = unquote(first)
        return second if second != data.strip() else None
    except Exception:
        return None

def decode_html_entities(data: str) -> Optional[str]:
    try:
        from html import unescape
        decoded = unescape(data.strip())
        return decoded if decoded != data.strip() else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  Morse Code
# ══════════════════════════════════════════════════════════════════

MORSE_TABLE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
    '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9',
    '.-.-.-':'.','--..--':',','..--..':'?','-..-.':'/','-....-':'-',
    '.--.-.':'@','---...':':','-.-.-.':';','-.--.-':')','-.--.':'(',
}

def decode_morse(data: str) -> Optional[str]:
    try:
        text = data.strip()
        if not all(c in '.- /|\n\t' for c in text):
            return None
        words = text.replace('|','/').replace('\n','/').split('/')
        result = []
        for word in words:
            chars = []
            for code in word.strip().split():
                if code in MORSE_TABLE:
                    chars.append(MORSE_TABLE[code])
                else:
                    return None
            if chars:
                result.append(''.join(chars))
        decoded = ' '.join(result)
        return decoded if decoded.strip() else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  Classical & CTF ciphers
# ══════════════════════════════════════════════════════════════════

def decode_atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            if ch.isupper():
                result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)
    return ''.join(result)

COMMON_VIGENERE_KEYS = [
    'key','secret','password','abc','flag','cipher','hack','leet',
    'admin','root','code','virus','ctf','crypto','hidden','stego',
    'pass','test','hio','hashitout','pwn','exploit','hacker',
]

def decode_vigenere(text: str, key: str) -> str:
    key = key.lower()
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

AFFINE_KEYS = [(3,7),(5,8),(7,3),(9,2),(11,5),(25,1),(7,11),(3,0),(5,0)]

def decode_affine(text: str, a: int, b: int) -> str:
    def mod_inv(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None
    try:
        a_inv = mod_inv(a, 26)
        if a_inv is None:
            return text
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((a_inv * (ord(ch) - base - b)) % 26 + base))
            else:
                result.append(ch)
        return ''.join(result)
    except Exception:
        return text

def decode_bacon(text: str) -> Optional[str]:
    try:
        clean = text.upper().replace(' ','').replace('/','')
        if all(c in 'AB' for c in clean) and len(clean) % 5 == 0:
            chars = []
            for i in range(0, len(clean), 5):
                val = int(clean[i:i+5].replace('A','0').replace('B','1'), 2)
                if 0 <= val <= 25:
                    chars.append(chr(val + ord('A')))
            return ''.join(chars) if chars else None
        if all(c in '01' for c in clean) and len(clean) % 5 == 0:
            chars = []
            for i in range(0, len(clean), 5):
                val = int(clean[i:i+5], 2)
                if 0 <= val <= 25:
                    chars.append(chr(val + ord('A')))
            return ''.join(chars) if chars else None
        return None
    except Exception:
        return None

def decode_rail_fence(text: str, rails: int) -> str:
    try:
        n = len(text)
        pattern = []
        rail = 0
        direction = 1
        for _ in range(n):
            pattern.append(rail)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        indices = sorted(range(n), key=lambda i: pattern[i])
        result = [''] * n
        for i, idx in enumerate(indices):
            result[idx] = text[i]
        return ''.join(result)
    except Exception:
        return text

def decode_polybius(data: str) -> Optional[str]:
    try:
        text = data.strip()
        if not all(c in '12345 ' for c in text):
            return None
        GRID = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        parts = text.replace(' ','')
        if len(parts) % 2 != 0:
            return None
        result = []
        for i in range(0, len(parts), 2):
            row = int(parts[i]) - 1
            col = int(parts[i+1]) - 1
            idx = row * 5 + col
            if 0 <= idx < len(GRID):
                result.append(GRID[idx])
            else:
                return None
        return ''.join(result)
    except Exception:
        return None

def decode_tap_code(data: str) -> Optional[str]:
    try:
        parts = data.strip().split()
        if len(parts) % 2 != 0:
            return None
        GRID = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        result = []
        for i in range(0, len(parts), 2):
            row = int(parts[i]) - 1
            col = int(parts[i+1]) - 1
            idx = row * 5 + col
            if 0 <= idx < len(GRID):
                result.append(GRID[idx])
            else:
                return None
        return ''.join(result)
    except Exception:
        return None

def decode_nato(data: str) -> Optional[str]:
    NATO = {
        'ALPHA':'A','BRAVO':'B','CHARLIE':'C','DELTA':'D','ECHO':'E',
        'FOXTROT':'F','GOLF':'G','HOTEL':'H','INDIA':'I','JULIET':'J',
        'KILO':'K','LIMA':'L','MIKE':'M','NOVEMBER':'N','OSCAR':'O',
        'PAPA':'P','QUEBEC':'Q','ROMEO':'R','SIERRA':'S','TANGO':'T',
        'UNIFORM':'U','VICTOR':'V','WHISKEY':'W','XRAY':'X','YANKEE':'Y',
        'ZULU':'Z',
    }
    try:
        words = data.strip().upper().split()
        if not words or not all(w in NATO for w in words):
            return None
        return ''.join(NATO[w] for w in words)
    except Exception:
        return None

def decode_leetspeak(data: str) -> str:
    LEET = {'0':'o','1':'i','3':'e','4':'a','5':'s','6':'g','7':'t','@':'a','$':'s','!':'i'}
    return ''.join(LEET.get(c, c) for c in data)


# ══════════════════════════════════════════════════════════════════
#  Misc encodings
# ══════════════════════════════════════════════════════════════════

def decode_quoted_printable(data: str) -> Optional[bytes]:
    try:
        result = quopri.decodestring(data.encode())
        return result if result != data.encode() else None
    except Exception:
        return None

def decode_uuencode(data: str) -> Optional[bytes]:
    try:
        import uu
        lines = data.strip().split('\n')
        if not lines[0].startswith('begin'):
            return None
        in_buf = io.BytesIO(data.encode())
        out_buf = io.BytesIO()
        uu.decode(in_buf, out_buf, quiet=True)
        return out_buf.getvalue()
    except Exception:
        return None

def decode_punycode(data: str) -> Optional[str]:
    try:
        if 'xn--' not in data.lower():
            return None
        decoded = data.strip().encode('ascii').decode('idna')
        return decoded if decoded != data.strip() else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  XOR
# ══════════════════════════════════════════════════════════════════

def try_xor_keys(data: bytes) -> List[Tuple[int, str]]:
    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('ascii')
            if is_mostly_printable(text):
                results.append((key, text))
        except Exception:
            pass
    return results

def try_xor_multibyte(data: bytes) -> List[Tuple[bytes, str]]:
    common_keys = [
        b'\xde\xad', b'\xbe\xef', b'\xca\xfe', b'\xba\xbe',
        b'\xff\xfe', b'\xaa\x55', b'\x55\xaa', b'\xde\xad\xbe\xef',
        b'\xca\xfe\xba\xbe', b'\x13\x37', b'\x41\x41', b'\x00\xff',
    ]
    results = []
    for key in common_keys:
        decoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        try:
            text = decoded.decode('ascii')
            if is_mostly_printable(text):
                results.append((key, text))
        except Exception:
            pass
    return results


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def is_mostly_printable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    return sum(1 for c in text if c in string.printable) / len(text) >= threshold

def is_mostly_words(text: str, wordlist: set, threshold: float = 0.35) -> bool:
    if not text or not wordlist:
        return False
    tokens = text.lower().split()
    if not tokens:
        return False
    matches = sum(1 for t in tokens if t.strip(string.punctuation) in wordlist)
    return (matches / len(tokens)) >= threshold

def safe_decode_bytes(data: bytes) -> str:
    for enc in ('utf-8', 'latin-1', 'ascii', 'cp1252'):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return data.decode('latin-1', errors='replace')

def bytes_to_hex_display(data: bytes, max_bytes: int = 64) -> str:
    snippet = data[:max_bytes]
    hex_str = ' '.join(f'{b:02X}' for b in snippet)
    if len(data) > max_bytes:
        hex_str += f' ... ({len(data)} bytes total)'
    return hex_str

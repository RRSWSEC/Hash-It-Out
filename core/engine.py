"""
core/engine.py - Analysis orchestrator for Hash It Out v3
"""

import os
import string
import datetime
from typing import Optional, List

from .decoders import (
    rot_n, rot47, rot5, rot18,
    decode_base2, decode_base8, decode_base10, decode_base16,
    decode_base32, decode_base32hex, decode_base32_crockford,
    decode_base36, decode_base45,
    decode_base58, decode_base58_flickr, decode_base62,
    decode_base64, decode_base64_url, decode_base64_mime,
    decode_base85, decode_ascii85, decode_z85,
    decode_base91, decode_base92,
    decode_hex, decode_hex_escaped,
    decode_url, decode_url_double, decode_html_entities,
    decode_morse,
    decode_quoted_printable, decode_uuencode, decode_punycode,
    decode_atbash, decode_vigenere, COMMON_VIGENERE_KEYS,
    decode_affine, AFFINE_KEYS,
    decode_bacon, decode_rail_fence, decode_polybius, decode_tap_code,
    decode_nato, decode_leetspeak,
    try_xor_keys, try_xor_multibyte,
    is_mostly_printable, is_mostly_words,
    safe_decode_bytes, bytes_to_hex_display,
)
from .filetypes import (
    detect_filetype,
    find_embedded_files,
    lsb_extract_text, lsb_extract_all_planes,
    scan_for_embedded_strings,
    extract_png_chunks, extract_jpeg_comments, extract_zip_comment,
    check_polyglot, try_zlib_decompress,
    scan_whitespace_stego, scan_unicode_stego,
)

MAX_REPORT_STRING_LEN = 1240


class Finding:
    def __init__(self, method: str, result_text: str = None,
                 result_bytes: bytes = None, filetype: tuple = None,
                 confidence: str = 'LOW', note: str = ''):
        self.method = method
        self.result_text = result_text
        self.result_bytes = result_bytes
        self.filetype = filetype
        self.confidence = confidence
        self.note = note
        self.timestamp = datetime.datetime.now()

    def display_result(self) -> str:
        if self.result_text:
            return self.result_text
        if self.result_bytes:
            return bytes_to_hex_display(self.result_bytes)
        return '[no output]'


class AnalysisEngine:
    def __init__(self, wordlist: set = None, output_dir: str = './output',
                 verbose: bool = True, flags: dict = None):
        self.wordlist = wordlist or set()
        self.output_dir = output_dir
        self.verbose = verbose
        self.flags = flags or {}
        os.makedirs(output_dir, exist_ok=True)

    def _do(self, *keys) -> bool:
        if self.flags.get('all'):
            return True
        decode_flags = ['rot','base','hex','binary','url','morse',
                        'cipher','xor','misc','stego','reverse','deep']
        if not any(self.flags.get(f) for f in decode_flags):
            return True
        return any(self.flags.get(k) for k in keys)

    # ── Main entry ───────────────────────────────────────────────

    def analyze(self, data: str, source_label: str = 'INPUT') -> List[Finding]:
        findings = []

        if self._do('rot'):
            findings += self._try_rots(data)
        if self._do('base'):
            findings += self._try_bases(data)
        if self._do('hex'):
            findings += self._try_hex(data)
        if self._do('binary'):
            findings += self._try_binary(data)
        if self._do('url'):
            findings += self._try_url(data)
        if self._do('morse'):
            findings += self._try_morse(data)
        if self._do('cipher'):
            findings += self._try_ciphers(data)
        if self._do('xor'):
            findings += self._try_xor(data)
        if self._do('misc'):
            findings += self._try_misc(data)
        if self._do('stego', 'deep'):
            findings += self._try_text_stego(data)
        if self._do('reverse'):
            for f in self._run_text_passes(data[::-1]):
                f.method = '[REVERSED] ' + f.method
                findings.append(f)

        raw = self._try_get_bytes(data)
        if raw and self._do('stego', 'deep'):
            findings += self._try_binary_stego(raw)

        for f in findings:
            if f.result_bytes and not f.filetype:
                ft = detect_filetype(f.result_bytes)
                if ft:
                    f.filetype = ft
                    f.confidence = 'HIGH'

        return findings

    def analyze_file(self, data: bytes, filename: str) -> List[Finding]:
        findings = []

        ft = detect_filetype(data)
        if ft:
            findings.append(Finding(
                method='File Magic Bytes (direct)',
                result_bytes=data, filetype=ft, confidence='HIGH',
                note=f'Input is {ft[1]}'))

        poly = check_polyglot(data)
        if poly:
            findings.append(Finding(
                method='Polyglot Detection',
                result_text='\n'.join(poly),
                confidence='HIGH',
                note='File valid in multiple formats simultaneously'))

        embedded = find_embedded_files(data)
        if embedded:
            summary = '\n'.join(
                f'  0x{pos:08X} : {desc} (.{ext})' for pos, ext, desc in embedded)
            findings.append(Finding(
                method='Embedded File Scan (all offsets)',
                result_text=summary,
                confidence='HIGH',
                note=f'{len(embedded)} embedded file type(s) detected'))
            for pos, ext, desc in embedded:
                findings.append(Finding(
                    method=f'Extracted: {desc} at offset 0x{pos:08X}',
                    result_bytes=data[pos:],
                    filetype=(ext, desc),
                    confidence='MEDIUM',
                    note='Sliced from detected signature to EOF'))

        if data[:8] == b'\x89PNG\r\n\x1a\n':
            findings += self._analyze_png(data)
        if data[:3] == b'\xFF\xD8\xFF':
            findings += self._analyze_jpeg(data)
        if data[:4] == b'PK\x03\x04':
            findings += self._analyze_zip(data)

        for label, result in lsb_extract_all_planes(data):
            conf, note = self._text_quality(result)
            findings.append(Finding(
                method=f'LSB Steganography ({label})',
                result_text=result, confidence=conf, note=note))

        decompressed = try_zlib_decompress(data)
        if decompressed:
            ft2 = detect_filetype(decompressed)
            if ft2:
                findings.append(Finding(
                    method='Zlib Decompress → File',
                    result_bytes=decompressed, filetype=ft2,
                    confidence='HIGH',
                    note=f'Decompressed to {ft2[1]}'))
            else:
                text = safe_decode_bytes(decompressed)
                if is_mostly_printable(text):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method='Zlib Decompress → Text',
                        result_text=text, confidence=conf, note=note))

        strings = scan_for_embedded_strings(data, min_len=6)
        interesting = [s for s in strings if self._has_word_content(s)]
        if interesting:
            findings.append(Finding(
                method='Embedded ASCII Strings',
                result_text='\n'.join(interesting[:60]),
                confidence='LOW',
                note=f'{len(interesting)} readable strings found in binary'))

        text_repr = data.decode('utf-8', errors='ignore')
        if text_repr.strip():
            for f in self._run_text_passes(text_repr):
                findings.append(f)

        ws = scan_whitespace_stego(text_repr)
        if ws:
            conf, note = self._text_quality(ws)
            findings.append(Finding(
                method='Whitespace Steganography (SNOW-style)',
                result_text=ws, confidence=conf,
                note='Found in trailing whitespace of text lines'))
        uc = scan_unicode_stego(text_repr)
        if uc:
            conf, note = self._text_quality(uc)
            findings.append(Finding(
                method='Unicode Zero-Width Steganography',
                result_text=uc, confidence=conf,
                note='Decoded from zero-width characters in text'))

        return findings

    # ── Format-specific deep dives ───────────────────────────────

    def _analyze_png(self, data: bytes) -> List[Finding]:
        findings = []
        chunks = extract_png_chunks(data)
        interesting_types = {'tEXt', 'zTXt', 'iTXt', 'cHRM', 'hIST', 'oFFs'}
        for chunk_type, chunk_data in chunks:
            if chunk_type in interesting_types:
                try:
                    text = chunk_data.decode('utf-8', errors='replace')
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method=f'PNG Chunk ({chunk_type})',
                        result_text=text, confidence=conf,
                        note=f'Data in PNG {chunk_type} chunk'))
                except Exception:
                    pass
            if chunk_type == 'zTXt':
                try:
                    import zlib
                    null_pos = chunk_data.index(0)
                    compressed = chunk_data[null_pos+2:]
                    decompressed = zlib.decompress(compressed)
                    text = decompressed.decode('utf-8', errors='replace')
                    conf, note = self._text_quality(text)
                    findings.append(Finding(
                        method='PNG zTXt Chunk (decompressed)',
                        result_text=text, confidence=conf,
                        note='Decompressed hidden text from PNG zTXt chunk'))
                except Exception:
                    pass
        return findings

    def _analyze_jpeg(self, data: bytes) -> List[Finding]:
        findings = []
        for comment in extract_jpeg_comments(data):
            conf, note = self._text_quality(comment)
            findings.append(Finding(
                method='JPEG Comment (COM segment)',
                result_text=comment, confidence=conf,
                note='Text in JPEG comment marker'))
        return findings

    def _analyze_zip(self, data: bytes) -> List[Finding]:
        findings = []
        comment = extract_zip_comment(data)
        if comment:
            conf, note = self._text_quality(comment)
            findings.append(Finding(
                method='ZIP Archive Comment',
                result_text=comment, confidence=conf,
                note='Text in ZIP end-of-central-directory comment'))
        return findings

    # ── Text decoder passes ──────────────────────────────────────

    def _try_rots(self, data: str) -> List[Finding]:
        findings = []
        for n in range(1, 26):
            decoded = rot_n(data, n)
            conf, note = self._text_quality(decoded)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'ROT{n}', result_text=decoded,
                    confidence=conf, note=note))
        for label, fn in [('ROT47', rot47), ('ROT18 (ROT13+ROT5)', rot18)]:
            decoded = fn(data)
            if decoded != data:
                conf, note = self._text_quality(decoded)
                if conf == 'HIGH':
                    findings.append(Finding(method=label, result_text=decoded,
                                            confidence=conf, note=note))
        return findings

    def _try_bases(self, data: str) -> List[Finding]:
        findings = []
        bases = [
            ('Base2 (Binary)',           decode_base2),
            ('Base8 (Octal)',            decode_base8),
            ('Base10 (Decimal bytes)',   decode_base10),
            ('Base16 (Hex)',             decode_base16),
            ('Base32',                   decode_base32),
            ('Base32 (Extended Hex)',    decode_base32hex),
            ('Base32 (Crockford)',       decode_base32_crockford),
            ('Base36',                   decode_base36),
            ('Base45',                   decode_base45),
            ('Base58 (Bitcoin)',         decode_base58),
            ('Base58 (Flickr)',          decode_base58_flickr),
            ('Base62',                   decode_base62),
            ('Base64',                   decode_base64),
            ('Base64 (URL-safe)',        decode_base64_url),
            ('Base64 (MIME)',            decode_base64_mime),
            ('Base85 (Python)',          decode_base85),
            ('Base85 (ASCII85/Adobe)',   decode_ascii85),
            ('Base85 (Z85/ZeroMQ)',      decode_z85),
            ('Base91',                   decode_base91),
            ('Base92',                   decode_base92),
        ]
        for name, fn in bases:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(
                    method=name, result_bytes=result,
                    filetype=ft, confidence='HIGH',
                    note=f'decoded binary → {ft[1]}'))
            else:
                text = safe_decode_bytes(result)
                if is_mostly_printable(text, threshold=0.75):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(method=name, result_text=text,
                                            confidence=conf, note=note))
        return findings

    def _try_hex(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Hexadecimal', decode_hex),
                           ('Hex (escaped \\x/% format)', decode_hex_escaped)]:
            result = fn(data)
            if not result:
                continue
            ft = detect_filetype(result)
            if ft:
                findings.append(Finding(method=f'{label} → Binary',
                                        result_bytes=result, filetype=ft,
                                        confidence='HIGH',
                                        note=f'hex decoded to {ft[1]}'))
            else:
                text = safe_decode_bytes(result)
                conf, note = self._text_quality(text)
                if conf in ('HIGH', 'MEDIUM'):
                    findings.append(Finding(method=f'{label} → ASCII',
                                            result_text=text,
                                            confidence=conf, note=note))
        return findings

    def _try_binary(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('Binary (01 string)', decode_base2),
                           ('Octal', decode_base8)]:
            result = fn(data)
            if result:
                text = safe_decode_bytes(result)
                conf, note = self._text_quality(text)
                findings.append(Finding(method=label, result_text=text,
                                        confidence=conf, note=note))
        return findings

    def _try_url(self, data: str) -> List[Finding]:
        findings = []
        for label, fn in [('URL Encoding (%XX)', decode_url),
                           ('Double URL Encoding', decode_url_double),
                           ('HTML Entities', decode_html_entities)]:
            result = fn(data)
            if result:
                conf, note = self._text_quality(result)
                findings.append(Finding(method=label, result_text=result,
                                        confidence=conf, note=note))
        return findings

    def _try_morse(self, data: str) -> List[Finding]:
        result = decode_morse(data)
        if result:
            conf, note = self._text_quality(result)
            return [Finding(method='Morse Code', result_text=result,
                            confidence=conf, note=note)]
        return []

    def _try_ciphers(self, data: str) -> List[Finding]:
        findings = []
        atbash = decode_atbash(data)
        if atbash != data:
            conf, note = self._text_quality(atbash)
            if conf == 'HIGH':
                findings.append(Finding(method='Atbash Cipher', result_text=atbash,
                                        confidence=conf, note=note))
        for key in COMMON_VIGENERE_KEYS:
            vig = decode_vigenere(data, key)
            if vig != data:
                conf, note = self._text_quality(vig)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Vigenère (key="{key}")',
                        result_text=vig, confidence=conf, note=note))
        for a, b in AFFINE_KEYS:
            aff = decode_affine(data, a, b)
            if aff != data:
                conf, note = self._text_quality(aff)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Affine Cipher (a={a}, b={b})',
                        result_text=aff, confidence=conf, note=note))
        bacon = decode_bacon(data)
        if bacon:
            conf, note = self._text_quality(bacon)
            findings.append(Finding(method="Bacon's Cipher",
                                    result_text=bacon, confidence=conf, note=note))
        for rails in range(2, 6):
            rf = decode_rail_fence(data, rails)
            if rf != data:
                conf, note = self._text_quality(rf)
                if conf == 'HIGH':
                    findings.append(Finding(
                        method=f'Rail Fence ({rails} rails)',
                        result_text=rf, confidence=conf, note=note))
        pb = decode_polybius(data)
        if pb:
            conf, note = self._text_quality(pb)
            findings.append(Finding(method='Polybius Square',
                                    result_text=pb, confidence=conf, note=note))
        tap = decode_tap_code(data)
        if tap:
            conf, note = self._text_quality(tap)
            findings.append(Finding(method='Tap Code',
                                    result_text=tap, confidence=conf, note=note))
        nato = decode_nato(data)
        if nato:
            conf, note = self._text_quality(nato)
            findings.append(Finding(method='NATO Phonetic Alphabet',
                                    result_text=nato, confidence=conf, note=note))
        leet = decode_leetspeak(data)
        if leet != data:
            conf, note = self._text_quality(leet)
            if conf == 'HIGH':
                findings.append(Finding(method='Leet Speak (1337)',
                                        result_text=leet, confidence=conf, note=note))
        return findings

    def _try_xor(self, data: str) -> List[Finding]:
        findings = []
        try:
            raw = data.encode('latin-1')
        except Exception:
            return findings
        for key, text in try_xor_keys(raw):
            conf, note = self._text_quality(text)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'XOR single-byte (key=0x{key:02X})',
                    result_text=text, confidence=conf, note=note))
        for key, text in try_xor_multibyte(raw):
            conf, note = self._text_quality(text)
            if conf == 'HIGH':
                findings.append(Finding(
                    method=f'XOR multi-byte (key=0x{key.hex().upper()})',
                    result_text=text, confidence=conf, note=note))
        return findings

    def _try_misc(self, data: str) -> List[Finding]:
        findings = []
        qp = decode_quoted_printable(data)
        if qp:
            try:
                text = qp.decode('utf-8')
                conf, note = self._text_quality(text)
                findings.append(Finding(method='Quoted-Printable',
                                        result_text=text, confidence=conf, note=note))
            except Exception:
                pass
        uu = decode_uuencode(data)
        if uu:
            ft = detect_filetype(uu)
            if ft:
                findings.append(Finding(method='UUEncoding', result_bytes=uu,
                                        filetype=ft, confidence='HIGH'))
            else:
                text = safe_decode_bytes(uu)
                if is_mostly_printable(text):
                    conf, note = self._text_quality(text)
                    findings.append(Finding(method='UUEncoding',
                                            result_text=text, confidence=conf, note=note))
        pny = decode_punycode(data)
        if pny:
            findings.append(Finding(method='Punycode', result_text=pny,
                                    confidence='MEDIUM', note='IDN/punycode decoded'))
        return findings

    def _try_text_stego(self, data: str) -> List[Finding]:
        findings = []
        ws = scan_whitespace_stego(data)
        if ws:
            conf, note = self._text_quality(ws)
            findings.append(Finding(
                method='Whitespace Steganography (SNOW)',
                result_text=ws, confidence=conf,
                note='Hidden in trailing spaces/tabs'))
        uc = scan_unicode_stego(data)
        if uc:
            conf, note = self._text_quality(uc)
            findings.append(Finding(
                method='Unicode Zero-Width Steganography',
                result_text=uc, confidence=conf,
                note='Hidden in zero-width Unicode characters'))
        return findings

    def _try_binary_stego(self, raw: bytes) -> List[Finding]:
        findings = []
        lsb = lsb_extract_text(raw)
        if lsb and is_mostly_printable(lsb):
            conf, note = self._text_quality(lsb)
            findings.append(Finding(
                method='LSB Steganography (bit-plane 0)',
                result_text=lsb, confidence=conf,
                note='Extracted from LSBs of input bytes'))
        ft = detect_filetype(raw)
        if ft:
            findings.append(Finding(
                method='File Signature (forward)',
                result_bytes=raw, filetype=ft, confidence='HIGH'))
        ft_rev = detect_filetype(raw[::-1])
        if ft_rev:
            findings.append(Finding(
                method='File Signature (reversed bytes)',
                result_bytes=raw[::-1], filetype=ft_rev, confidence='MEDIUM',
                note='Reversed byte order produced valid file signature'))
        return findings

    # ── Helpers ──────────────────────────────────────────────────

    def _run_text_passes(self, data: str) -> List[Finding]:
        findings = []
        findings += self._try_rots(data)
        findings += self._try_bases(data)
        findings += self._try_hex(data)
        findings += self._try_binary(data)
        findings += self._try_url(data)
        findings += self._try_morse(data)
        findings += self._try_ciphers(data)
        return findings

    def _try_get_bytes(self, data: str) -> Optional[bytes]:
        for fn in (decode_hex, decode_base64):
            b = fn(data)
            if b and detect_filetype(b):
                return b
        return None

    def _text_quality(self, text: str) -> tuple:
        if not text or not text.strip():
            return ('LOW', 'empty result')
        ratio = sum(1 for c in text if c in string.printable) / len(text)
        word_match = is_mostly_words(text, self.wordlist) if self.wordlist else False
        if word_match and ratio > 0.85:
            return ('HIGH', 'matches dictionary words')
        elif ratio > 0.95:
            return ('MEDIUM', 'mostly printable ASCII')
        elif ratio > 0.75:
            return ('LOW', 'partially printable')
        return ('LOW', 'low printable ratio')

    def _has_word_content(self, text: str) -> bool:
        if not self.wordlist:
            return len(text) > 8
        tokens = text.lower().split()
        return any(t.strip(string.punctuation) in self.wordlist for t in tokens)

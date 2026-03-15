"""
core/filetypes.py - File type detection, stego extraction, nested container analysis
Hash It Out v3
"""

import struct
import zlib
from typing import Optional, Tuple, List


FILE_SIGNATURES = [
    # Images
    (b'\xFF\xD8\xFF',           0,  'jpg',    'JPEG Image'),
    (b'\x89PNG\r\n\x1a\n',     0,  'png',    'PNG Image'),
    (b'GIF87a',                 0,  'gif',    'GIF Image (87a)'),
    (b'GIF89a',                 0,  'gif',    'GIF Image (89a)'),
    (b'BM',                     0,  'bmp',    'BMP Image'),
    (b'II*\x00',                0,  'tif',    'TIFF (little-endian)'),
    (b'MM\x00*',                0,  'tif',    'TIFF (big-endian)'),
    (b'RIFF',                   0,  'riff',   'RIFF Container'),
    (b'\x00\x00\x01\x00',      0,  'ico',    'ICO Icon'),
    (b'8BPS',                   0,  'psd',    'Photoshop PSD'),
    (b'JFIF',                   6,  'jpg',    'JPEG (JFIF)'),
    (b'Exif',                   6,  'jpg',    'JPEG (EXIF)'),
    (b'IHDR',                   12, 'png',    'PNG (IHDR chunk)'),
    (b'P1\n',                   0,  'pbm',    'PBM Bitmap'),
    (b'P2\n',                   0,  'pgm',    'PGM Greymap'),
    (b'P3\n',                   0,  'ppm',    'PPM Pixmap'),
    (b'P4\n',                   0,  'pbm',    'PBM Binary'),
    (b'P5\n',                   0,  'pgm',    'PGM Binary'),
    (b'P6\n',                   0,  'ppm',    'PPM Binary'),
    # Documents
    (b'%PDF-',                  0,  'pdf',    'PDF Document'),
    (b'\xD0\xCF\x11\xE0',      0,  'doc',    'MS Office Legacy'),
    (b'%!PS-Adobe',             0,  'ps',     'PostScript'),
    (b'{\rtf',                  0,  'rtf',    'Rich Text Format'),
    # Archives
    (b'PK\x03\x04',             0,  'zip',    'ZIP Archive'),
    (b'PK\x05\x06',             0,  'zip',    'ZIP (empty)'),
    (b'Rar!\x1a\x07\x00',      0,  'rar',    'RAR v4'),
    (b'Rar!\x1a\x07\x01\x00',  0,  'rar',    'RAR v5'),
    (b'\x1f\x8b',               0,  'gz',     'Gzip'),
    (b'BZh',                    0,  'bz2',    'Bzip2'),
    (b'\xfd7zXZ\x00',           0,  'xz',     'XZ Archive'),
    (b'7z\xbc\xaf\x27\x1c',    0,  '7z',     '7-Zip'),
    (b'MSCF',                   0,  'cab',    'MS Cabinet'),
    (b'LZIP',                   0,  'lz',     'LZIP'),
    (b'\x1f\xa0',               0,  'z',      'Unix Compress'),
    # Executables
    (b'\x7fELF',                0,  'elf',    'ELF Executable'),
    (b'MZ',                     0,  'exe',    'PE Executable'),
    (b'\xCA\xFE\xBA\xBE',      0,  'class',  'Java Class'),
    (b'\xCE\xFA\xED\xFE',      0,  'macho',  'Mach-O 32-bit'),
    (b'\xCF\xFA\xED\xFE',      0,  'macho',  'Mach-O 64-bit'),
    (b'#!',                     0,  'sh',     'Shell Script'),
    (b'dex\n',                  0,  'dex',    'Android DEX'),
    # Audio/Video
    (b'OggS',                   0,  'ogg',    'OGG'),
    (b'fLaC',                   0,  'flac',   'FLAC Audio'),
    (b'ID3',                    0,  'mp3',    'MP3 (ID3)'),
    (b'\xFF\xFB',               0,  'mp3',    'MP3'),
    (b'ftyp',                   4,  'mp4',    'MPEG-4'),
    (b'WAVEfmt',                8,  'wav',    'WAV Audio'),
    (b'\x30\x26\xB2\x75',      0,  'wmv',    'Windows Media'),
    (b'FWS',                    0,  'swf',    'Flash SWF'),
    (b'CWS',                    0,  'swf',    'Flash SWF (compressed)'),
    # Network
    (b'\xD4\xC3\xB2\xA1',      0,  'pcap',   'PCAP (LE)'),
    (b'\xA1\xB2\xC3\xD4',      0,  'pcap',   'PCAP (BE)'),
    (b'\x0a\x0d\x0d\x0a',      0,  'pcapng', 'PCAPng'),
    # Code/Text
    (b'<?xml',                  0,  'xml',    'XML'),
    (b'<?php',                  0,  'php',    'PHP'),
    (b'<!DOCTYPE',              0,  'html',   'HTML'),
    (b'<html',                  0,  'html',   'HTML'),
    (b'{"',                     0,  'json',   'JSON'),
    (b'[{',                     0,  'json',   'JSON Array'),
    # Crypto/Keys
    (b'-----BEGIN',             0,  'pem',    'PEM Key/Cert'),
    (b'ssh-rsa',                0,  'pub',    'SSH RSA Key'),
    (b'ssh-ed25519',            0,  'pub',    'SSH Ed25519 Key'),
    (b'OpenSSH',                0,  'key',    'OpenSSH Private Key'),
    (b'PuTTY',                  0,  'ppk',    'PuTTY Key'),
    # Fax / TIFF variants (CTF-relevant)
    (b'II\x2a\x00',             0,  'tif',    'TIFF/FAX (LE)'),
    (b'MM\x00\x2a',             0,  'tif',    'TIFF/FAX (BE)'),
    # Misc
    (b'SQLite format 3',        0,  'db',     'SQLite DB'),
    (b'StegHide',               0,  'steg',   'Steghide marker'),
    (b'SIMPLE  =',              0,  'fits',   'FITS Astronomical Data'),
    (b'wOFF',                   0,  'woff',   'Web Font WOFF'),
    (b'\x00\x01\x00\x00',      0,  'ttf',    'TrueType Font'),
    (b'OTTO',                   0,  'otf',    'OpenType Font'),
]


def detect_filetype(data: bytes) -> Optional[Tuple[str, str]]:
    for magic, offset, ext, desc in FILE_SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            if magic == b'RIFF' and len(data) >= 12:
                sub = data[8:12]
                if sub == b'WEBP': return ('webp', 'WebP Image')
                if sub == b'WAVE': return ('wav',  'WAV Audio')
                if sub == b'AVI ': return ('avi',  'AVI Video')
            return (ext, desc)
    return None


def find_embedded_files(data: bytes) -> List[Tuple[int, str, str]]:
    """
    Scan entire binary for file signatures at any offset.
    Catches files hidden/appended inside other files  -  core CTF technique.
    """
    found = []
    limit = min(len(data), 100_000_000)
    for magic, offset_hint, ext, desc in FILE_SIGNATURES:
        start = 1
        while True:
            pos = data.find(magic, start, limit)
            if pos == -1:
                break
            found.append((pos, ext, desc))
            start = pos + 1
    seen = set()
    deduped = []
    for pos, ext, desc in sorted(found):
        if ext not in seen:
            seen.add(ext)
            deduped.append((pos, ext, desc))
    return deduped


def lsb_extract_text(data: bytes, max_chars: int = 4000) -> Optional[str]:
    try:
        bits = [byte & 1 for byte in data]
        chars = []
        for i in range(0, min(len(bits) - 7, max_chars * 8), 8):
            byte_val = sum(bits[i + j] << (7 - j) for j in range(8))
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126 or byte_val in (9, 10, 13):
                chars.append(chr(byte_val))
            else:
                break
        result = ''.join(chars)
        return result if len(result) >= 4 else None
    except Exception:
        return None


def lsb_extract_all_planes(data: bytes) -> List[Tuple[str, str]]:
    results = []
    for plane in range(8):
        try:
            bits = [(byte >> plane) & 1 for byte in data]
            chars = []
            for i in range(0, min(len(bits) - 7, 3200), 8):
                byte_val = sum(bits[i + j] << (7 - j) for j in range(8))
                if byte_val == 0:
                    break
                if 32 <= byte_val <= 126 or byte_val in (9, 10, 13):
                    chars.append(chr(byte_val))
                else:
                    break
            result = ''.join(chars)
            if len(result) >= 4:
                results.append((f'LSB bit-plane {plane}', result))
        except Exception:
            pass
    return results


def scan_for_embedded_strings(data: bytes, min_len: int = 5) -> List[str]:
    results = []
    current = []
    for byte in data:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append(''.join(current))
            current = []
    if len(current) >= min_len:
        results.append(''.join(current))
    return results


def extract_png_chunks(data: bytes) -> List[Tuple[str, bytes]]:
    chunks = []
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return chunks
    pos = 8
    while pos + 12 <= len(data):
        try:
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
            chunk_data = data[pos+8:pos+8+length]
            chunks.append((chunk_type, chunk_data))
            pos += 12 + length
        except Exception:
            break
    return chunks


def extract_jpeg_comments(data: bytes) -> List[str]:
    comments = []
    pos = 0
    while pos < len(data) - 1:
        if data[pos] == 0xFF and data[pos+1] == 0xFE:
            if pos + 4 <= len(data):
                length = struct.unpack('>H', data[pos+2:pos+4])[0]
                comment = data[pos+4:pos+2+length]
                comments.append(comment.decode('utf-8', errors='replace'))
                pos += 2 + length
            else:
                break
        else:
            pos += 1
    return comments


def extract_zip_comment(data: bytes) -> Optional[str]:
    try:
        eocd = data.rfind(b'PK\x05\x06')
        if eocd == -1:
            return None
        comment_len = struct.unpack('<H', data[eocd+20:eocd+22])[0]
        if comment_len > 0:
            return data[eocd+22:eocd+22+comment_len].decode('utf-8', errors='replace')
        return None
    except Exception:
        return None


def check_polyglot(data: bytes) -> List[str]:
    hits = []
    types_found = set()
    for magic, offset, ext, desc in FILE_SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            types_found.add(ext)
    if len(data) > 22:
        tail = data[-65536:]
        for magic, offset, ext, desc in FILE_SIGNATURES:
            pos = tail.find(magic)
            if pos != -1 and ext not in types_found:
                types_found.add(ext)
                hits.append(f'Appended {desc} detected at tail (offset -{len(tail)-pos})')
    if len(types_found) > 1:
        hits.insert(0, f'POLYGLOT: valid signatures for: {", ".join(sorted(types_found))}')
    return hits


def try_zlib_decompress(data: bytes) -> Optional[bytes]:
    for skip in range(0, min(16, len(data))):
        try:
            result = zlib.decompress(data[skip:])
            if result:
                return result
        except Exception:
            pass
    for wbits in (15, -15, 47):
        try:
            result = zlib.decompress(data, wbits)
            if result:
                return result
        except Exception:
            pass
    return None


def scan_whitespace_stego(text: str) -> Optional[str]:
    """SNOW-style: trailing spaces=0, tabs=1"""
    try:
        lines = text.split('\n')
        bits = []
        for line in lines:
            stripped = line.rstrip()
            trail = line[len(stripped):]
            for ch in trail:
                if ch == ' ':
                    bits.append('0')
                elif ch == '\t':
                    bits.append('1')
        if len(bits) < 8:
            return None
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(''.join(bits[i:i+8]), 2)
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
        decoded = ''.join(result)
        return decoded if len(decoded) >= 3 else None
    except Exception:
        return None


def scan_unicode_stego(text: str) -> Optional[str]:
    """Zero-width character steganography"""
    ZWCHARS = {
        '\u200b': '0', '\u200c': '1', '\u200d': '1',
        '\u2060': '0', '\ufeff': '0',
    }
    try:
        bits = [ZWCHARS[ch] for ch in text if ch in ZWCHARS]
        if len(bits) < 8:
            return None
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(''.join(bits[i:i+8]), 2)
            if byte_val == 0:
                break
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
        decoded = ''.join(result)
        return decoded if len(decoded) >= 2 else None
    except Exception:
        return None

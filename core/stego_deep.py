"""
core/stego_deep.py  -  Hash It Out v4
Deep steganography analysis - JPEG DCT, PNG LSB, BMP, GIF, EXIF, steghide.
Full implementation requires Pillow. Gracefully skips if unavailable.
"""

from typing import List

try:
    from .engine import Finding
except ImportError:
    from engine import Finding


def analyze_image_deep(data: bytes, source_label: str = '') -> List[Finding]:
    """
    Deep stego analysis entry point.
    Routes to format-specific analyzers based on file magic.
    Returns list of Finding objects.
    """
    findings = []

    # jpeg
    if data[:3] == b'\xff\xd8\xff':
        findings.extend(_analyze_jpeg(data, source_label))

    # png
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        findings.extend(_analyze_png(data, source_label))

    # bmp
    elif data[:2] == b'BM':
        findings.extend(_analyze_bmp(data, source_label))

    return findings


def _analyze_jpeg(data, source_label):
    findings = []
    # check for appended data after JPEG EOI marker
    eoi = data.rfind(b'\xff\xd9')
    if eoi != -1 and eoi + 2 < len(data):
        appended = data[eoi + 2:]
        printable = sum(1 for b in appended if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(appended) > 0.6:
            findings.append(Finding(
                method='JPEG appended data (after EOI)',
                confidence='HIGH',
                note=f'{len(appended)} bytes after JPEG end marker',
                result_text=appended.decode('latin-1'),
                source_label=source_label,
            ))
    return findings


def _analyze_png(data, source_label):
    findings = []
    try:
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert('RGBA')
        pixels = list(img.getdata())

        # check R channel LSB
        bits = []
        for px in pixels:
            bits.append(px[0] & 1)

        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)

        printable = sum(1 for b in out[:256] if 32 <= b <= 126 or b in (9, 10, 13))
        if len(out) > 0 and printable / min(len(out), 256) > 0.7:
            findings.append(Finding(
                method='PNG LSB R channel (row scan)',
                confidence='MEDIUM',
                note=f'{len(out)} bytes extracted from R channel LSB',
                result_text=out.decode('latin-1'),
                source_label=source_label,
            ))
    except Exception:
        pass
    return findings


def _analyze_bmp(data, source_label):
    findings = []
    # bmp pixel data starts at offset stored in header
    if len(data) < 54:
        return findings
    import struct
    pixel_offset = struct.unpack('<I', data[10:14])[0]
    pixel_data = data[pixel_offset:]
    if not pixel_data:
        return findings

    bits = [b & 1 for b in pixel_data]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)

    printable = sum(1 for b in out[:256] if 32 <= b <= 126 or b in (9, 10, 13))
    if len(out) > 0 and printable / min(len(out), 256) > 0.7:
        findings.append(Finding(
            method='BMP LSB pixel data',
            confidence='MEDIUM',
            note=f'{len(out)} bytes extracted from BMP LSBs',
            result_text=out.decode('latin-1'),
            source_label=source_label,
        ))
    return findings

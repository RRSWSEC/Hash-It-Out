"""
core/carver.py  -  Hash It Out v4
Recursive file carving: finds embedded files by magic bytes,
extracts them, and feeds them back into the analysis pipeline.
"""

import io
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Callable


# ── Magic Signatures ──────────────────────────────────────────────────────────

@dataclass
class CarveHit:
    offset: int
    ext: str
    label: str
    data: bytes
    source: str
    depth: int
    children: list = field(default_factory=list)
    note: str = ''


MAGIC = [
    (b'\x89PNG\r\n\x1a\n',  'png',  'PNG Image',        67,     True),
    (b'\xff\xd8\xff',        'jpg',  'JPEG Image',        100,    True),
    (b'GIF87a',              'gif',  'GIF Image',         35,     True),
    (b'GIF89a',              'gif',  'GIF Image',         35,     True),
    (b'BM',                  'bmp',  'BMP Image',         54,     False),
    (b'II*\x00',             'tiff', 'TIFF Image (LE)',   8,      False),
    (b'MM\x00*',             'tiff', 'TIFF Image (BE)',   8,      False),
    (b'PK\x03\x04',          'zip',  'ZIP Archive',       30,     True),
    (b'PK\x05\x06',          'zip',  'ZIP Empty',         22,     False),
    (b'Rar!\x1a\x07\x00',   'rar',  'RAR Archive',       20,     False),
    (b'Rar!\x1a\x07\x01',   'rar',  'RAR5 Archive',      20,     False),
    (b'\x1f\x8b',            'gz',   'GZIP Stream',       18,     False),
    (b'BZh',                 'bz2',  'BZIP2 Stream',      10,     False),
    (b'7z\xbc\xaf\x27\x1c', '7z',   '7-Zip Archive',     32,     False),
    (b'%PDF',                'pdf',  'PDF Document',      100,    True),
    (b'\x7fELF',             'elf',  'ELF Binary',        52,     False),
    (b'MZ',                  'exe',  'PE/EXE Binary',     64,     False),
    (b'\xca\xfe\xba\xbe',   'class','Java Class',        10,     False),
    (b'RIFF',                'riff', 'RIFF Container',    12,     True),
    (b'OggS',                'ogg',  'OGG Stream',        27,     False),
    (b'fLaC',                'flac', 'FLAC Audio',        42,     False),
    (b'ID3',                 'mp3',  'MP3 Audio',         10,     False),
    (b'SQLite format 3',     'db',   'SQLite DB',         100,    False),
    (b'\x00\x01\x00\x00SF', 'ttf',  'TrueType Font',     12,     False),
    (b'OTTO',                'otf',  'OpenType Font',     12,     False),
]
MAGIC.sort(key=lambda x: len(x[0]), reverse=True)


def _find_jpeg_end(data, start):
    i = start + 2
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1; continue
        m = data[i + 1]
        if m == 0xD9: return i + 2
        if m in (0x01,) or (0xD0 <= m <= 0xD8): i += 2; continue
        if i + 3 >= len(data): break
        i += 2 + struct.unpack('>H', data[i+2:i+4])[0]
    return len(data)

def _find_png_end(data, start):
    i = start + 8
    while i + 8 <= len(data):
        l = struct.unpack('>I', data[i:i+4])[0]
        t = data[i+4:i+8]
        i += 12 + l
        if t == b'IEND': return i
    return len(data)

def _find_gif_end(data, start):
    p = data.find(b'\x3b', start+6); return p+1 if p!=-1 else len(data)

def _find_zip_end(data, start):
    p = data.rfind(b'PK\x05\x06', start)
    if p == -1: return len(data)
    c = struct.unpack('<H', data[p+20:p+22])[0] if p+22 <= len(data) else 0
    return p + 22 + c

def _find_pdf_end(data, start):
    p = data.find(b'%%EOF', start); return p+5 if p!=-1 else len(data)

def _find_riff_end(data, start):
    if start+8 <= len(data): return start+8+struct.unpack('<I',data[start+4:start+8])[0]
    return len(data)

def _find_bmp_end(data, start):
    if start+6 <= len(data): return start+struct.unpack('<I',data[start+2:start+6])[0]
    return len(data)

_END_FINDERS = {'jpg':_find_jpeg_end,'png':_find_png_end,'gif':_find_gif_end,'zip':_find_zip_end,'pdf':_find_pdf_end,'riff':_find_riff_end,'bmp':_find_bmp_end}


class FileCarver:
    def __init__(self, max_depth=5, min_size=16, output_dir=None, save_carved=True):
        self.max_depth=max_depth; self.min_size=min_size
        self.output_dir=output_dir; self.save_carved=save_carved
        self._seen_hashes=set()

    def carve(self, data, source_label, depth=0):
        if depth > self.max_depth: return []
        import hashlib
        h = hashlib.md5(data).hexdigest()
        if h in self._seen_hashes: return []
        self._seen_hashes.add(h)
        hits = []
        scan_start = min(len(data), 8) if depth==0 else 0
        for offset in range(scan_start, len(data)-4):
            for sig,ext,label,min_sz,has_end in MAGIC:
                slen=len(sig)
                if data[offset:offset+slen]!=sig: continue
                rem=len(data)-offset
                if rem<max(slen,min_sz,self.min_size): break
                finder=_END_FINDERS.get(ext)
                try: end=finder(data,offset) if finder else len(data)
                except: end=len(data)
                emb=data[offset:end]
                if len(emb)<self.min_size: break
                hit=CarveHit(offset=offset,ext=ext,label=label,data=emb,source=source_label,depth=depth,note=f'offset 0x{offset:x}')
                if depth+1<=self.max_depth:
                    hit.children=self.carve(emb,f'{label}@0x{offset:x}',depth+1)
                hits.append(hit); break
        return hits

    def _save(self,data,ext,source,offset):
        os.makedirs(self.output_dir,exist_ok=True)
        import re,datetime
        safe=re.sub(r'[^\w]','_',source)[:20]
        ts=datetime.datetime.now().strftime('%H%M%S%f')[:10]
        path=os.path.join(self.output_dir,f'carved_{safe}_{offset:x}_{ts}.{ext}')
        open(poth,'wb').write(data); return path


def format_carve_tree(hits, indent=0):
    lines=[]
    prefix='  '*indent
    for i,hit in enumerate(hits):
        c='└─' if i==len(hits)-1 else '├
        lines.append(f'{prefix}{c} [{hit.label}] @ r{hit.offset:x}')
        if hit.children: lines.append(format_carve_tree(hit.children,indent+1))
    return '\n'.join(lines)

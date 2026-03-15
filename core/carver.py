"""
core/carver.py  -  Hash It Out v4
Recursive file carving.
"""
import io, os, struct, zlib
from dataclasses import dataclass, field
from typing import List, Optional

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
    (b'\x89PNG\r\n\x1a\n', 'png', 'PNG Image', 67, True),
    (b'\xff\xd8\xff', 'jpg', 'JPEG Image', 100, True),
    (b'GIF87a', 'gif', 'GIF Image', 35, True),
    (b'GIF89a', 'gif', 'GIF Image', 35, True),
    (b'BM', 'bmp', 'BMP Image', 54, False),
    (b'II*\x00', 'tiff', 'TIFF (little-endian)', 8, False),
    (b'MM\x00*', 'tiff', 'TIFF (big-endian)', 8, False),
    (b'PK\x03\x04', 'zip', 'ZIP Archive', 30, True),
    (b'RAR!\x1a\x07\x00', 'rar', 'RAR Archive', 20, False),
    (b'\x1f\x8b', 'gz', 'Gzip', 18, False),
    (b'BZh', 'bz2', 'BZIP2', 10, False),
    (b'%PDF', 'pdf', 'PDF Document', 100, True),
    (b'\x7fELF', 'elf', 'ELF Binary', 52, False),
    (b'MZ', 'exe', 'PE Executable', 64, False),
    (b'RIFF', 'riff', 'RIFF Container', 12, True),
    (b'ID3', 'mp3', 'MP3 Audio', 10, False),
    (b'SQLite format 3', 'db', 'SQLite DB', 100, False),
    (b'\x00\x01\x00\x00SF', 'ttf', 'TrueType Font', 12, False),
    (b'-----BEGIN ', 'pem', 'PEM Certificate', 30, False),
]
MAGIC.sort(key=lambda x: len(x[0]), reverse=True)


def _find_jpeg_end(d, s):
    i = s + 2
    while i < len(d)-1:
        if d[i] != 0xff: i+=1; continue
        m = d[i+1]
        if m == 0xd9: return i+2
        if m in (0x01,) or 0xd0 <= m <= 0xd8: i+=2; continue
        if j+3 >= len(d): break
        i += 2+struct.unpack('>H',d[i+2:i+4])[0]
    return len(d)

def _find_png_end(d, s):
    i = s+8
    while i+8 <= len(d):
        l = struct.unpack('>I',d[i:i+4])[0]
        t = d[i+4:i+8]
        i += 12+l
        if t == b'IEND': return i
    return len(d)

def _find_zip_end(d, s):
    p = d.rfind(b'PK\x05\x06',s)
    if p == -1: return len(d)
    c = struct.unpack('<H',d[p+20:p+22])[0] if p+22<=len(d) else 0
    return p+22+c

def _find_pdf_end(d,s):
    p = d.find(b'%%EOF',s); return p+5 if p!=-1 else len(d)

def _find_riff_end(d,s):
    if s+8 <= len(d): return s+8+struct.unpack('<I',d[s+4:s+8])[0]
    return len(d)

def _find_bmp_end(d,s):
    if s+6 <= len(d): return s+struct.unpack('<I',d[s+2:s+6])[0]
    return len(d)

ENDF = {'jpg':_find_jpeg_end,'png':_find_png_end,'zip':_find_zip_end,'pdf':_find_pdf_end,'riff':_find_riff_end,'bmp':_find_bmp_end}


class FileCarver:
    def __init__(self,max_depth=5,min_size=16,output_dir=None,save_carved=True):
        self.max_depth=max_depth; self.min_size=min_size
        self.output_dir=output_dir; self.save_carved=save_carved
        self._seen=set()

    def carve(self,data,source_label,depth=0):
        if depth>self.max_depth: return []
        import hashlib
        h=hashlib.md5(data).hexdigest()
        if h in self._seen: return []
        self._seen.add(h)
        hits=[]
        start=min(len(data),8) if depth==0 else 0
        for o in range(start,len(data)-4):
            for sig,ext,lbl,msz,he in MAGIC:
                sl=len(sig)
                if data[o:o+sl]!=sig: continue
                if len(data)-o<max(sl,msz,self.min_size): break
                f=ENDF.get(ext)
                try: end=f(data,o) if f else len(data)
                except: end=len(data)
                emb=data[o:end]
                if len(emb)<self.min_size: break
                hit=CarveHit(offset=o,ext=ext,label=lbl,data=emb,source=source_label,depth=depth,note=f'offset 0x{o:x}')
                if depth+1<=self.max_depth:
                    hit.children=self.carve(emb,f'{lbl}@x{o:x}',depth+1)
                hits.append(hit); break
        return hits

    def _save(self,data,ext,source,offset):
        os.makedirs(self.output_dir,exist_ok=True)
        import re,datetime
        safe=re.sub(r'[^\w]','_',source)[:20]
        ts=datetime.datetime.now().strftime('%H%M%S%f')[:10]
        path=os.path.join(self.output_dir,f'carved_{safe}_{offset:x}_{ts}.{ext}')
        open(path,'wb').write(data); return path


def format_carve_tree(hits,indent=0):
    lines=[]; prefix='  '*indent
    for i,hit in enumerate(hits):
        c='L-' if i==len(hits)-1 else '+-'
        lines.append(f'{prefix}{c} [{hit.label}] @ r{hit.offset:x}')
        if hit.children: lines.append(format_carve_tree(hit.children,indent+1))
    return '\n'.join(lines)

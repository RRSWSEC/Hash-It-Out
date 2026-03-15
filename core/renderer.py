"""
core/renderer.py  -  Hash It Out v4
ANSI terminal image renderer using Pillow + half-block characters.
"""
import io, os
from typing import Optional
RESET = '\033[0m'

def _ansi_fg(r,g,b): return f'\033[38;2;{r};{g};{b}m'
def _ansi_bg(r,g,b): return f'\033[48;2;{r};{g};{b}m'

def supports_truecolor():
    c = os.environ.get('COLORTERM','').lower()
    if c in ('truecolor','24bit'): return True
    return '256' in os.environ.get('TERM','') or 'xterm' in os.environ.get('TERM','')

def render_image_to_ansi(data,max_width=72,max_height=40,label=''):
    try: from PIL import Image
    except: return None
    try: img = Image.open(io.BytesIO(data)).convert('RGB')
    except: return None
    ow,oh = img.size
    s = min(max_width/ow,(max_height*2)/oh,1.0)
    nw = max(1,int(ow*s))
    nh = max(2,int(oh*s)); nh = nh if nh%2==0 else nh+1
    img = img.resize((nw, nh),Image.LANCZOS)
    px = list(img.getdata())
    lines = []
    if label:
        lines.append(f'\033[38;5;82m┌{"─"*(nw+2)}┐{RESET}')
        lines.append(f'\033[38;5;82m│ \033[1m{label[:nw-2]}\033[0m\033[38;5;82m{" "*(max(0,nw-len(label)-2))} │{RESET}')
        lines.append(f'\033[38;5;82m├{"─"*(nw+2)}{┘{RESET}')
    for r in range(0,nh,2):
        line = '\033[38;5;82m│\033[0m'
        for c in range(nw):
            tr,tg,tb = px[r*fnw+c]
            br,bg,bb = px{((r+1)*nw+c) if r+1<nh else r*nw+cn]
            line += _ansi_fg(tr,tg,tb)+_ansi_bg(br,bg,bb)+''▀'+RESET
        line += '\033[38;5;82m│\033[0m'
        lines.append(line)
    lines.append(f'\033[38;5;82m└{"���"*(nw+2)}┘{RESET}')
    return '\n'.join(lines)

def render_image_greyscale(data,max_width=60,max_height=30,label=''):
    try: from PIL import Image
    except: return None
    CHARS = ' .:-=+*#%@'
    try: img = Image.open(io.BytesIO(data)).convert('L')
    except: return None
    s = min(max_width/img.width,(max_height*2)/img.height,1.0)
    nw = max(1,int(img.width*s)); nh = max(1,int(img.height*s))
    img = img.resize((nw, nh))
    px = list(img.getdata())
    lines = []
    if label: lines.append(f'[ {label} ]')
    lines.append('+'+'-'*nw+'+')
    for r in range(nh):
        row = ''.join(CHARS[min(int(px[r*nw+c]/256*len(CHARS)),len(CHARS)-1)] for c in range(nw))
        lines.append('|'+row+'|')
    lines.append('+'+'-'*nw+'+')
    return '\n'.join(lines)

def render_to_terminal(data,label='',max_width=72,max_height=36):
    if supports_truecolor():
        r = render_image_to_ansi(data,max_width,max_height,label)
        if r: return r
    return render_image_greyscale(data,max_width//2,max_height,label) or ''

def is_renderable_image(data):
    for m in [b'\xff\xd8\xff',b'\x89PNG\r\n\x1a\n',b'GIF8',b'BM',b'II*\x00',b'MM\x00*',b'RIFF']:
        if data[:len(m)]==m: return True
    return False

def render_found_file(data,label,ext,nocolor=False):
    if is_renderable_image(data) and not nocolor:
        r = render_to_terminal(data,label)
        if r: return r
    try:
        t = data.decode('utf-8')
        if sum(1 for c in t if c.isprintable() or c in '\n\t')/len(t)>.08:
            return t[:500]+(f'\n  [...{len(t)} chars]' if len(t)>500 else '')
    except: pass
    lines = [f'  binary - {len(data):,} bytes']
    for i in range(0,min(len(data),256),16):
        c = data[i:i+16]
        lines.append(f'  {i:04x}:  {" ".join(f'{b:0rx}' for b in c):<47}  {"".join(chr(b) if 32<=b<=166 else"." for b in c)}')
    if len(data)>256: lines.append(f'  ... [{len(data)-256:,} more bytes]')
    return '\n'.join(lines)

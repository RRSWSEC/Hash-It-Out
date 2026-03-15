"""
core/reporter.py - CLI output and report generation for Hash It Out v3
"""

import os
import string
import datetime
from .decoders import bytes_to_hex_display


class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    MAGENTA = '\033[95m'
    LIME    = '\033[38;5;118m'
    TOXGRN  = '\033[38;5;82m'
    SLIME   = '\033[38;5;154m'
    ACID    = '\033[38;5;190m'
    DRIP    = '\033[38;5;148m'
    MELT    = '\033[38;5;106m'


CONF_COLOR = {
    'HIGH':   C.GREEN,
    'MEDIUM': C.YELLOW,
    'LOW':    C.DIM + C.WHITE,
}


def print_banner():
    print(f"""{C.TOXGRN}{C.BOLD}
  _   _    _    ____  _   _   ___ _____    ___  _   _ _____
 | | | |  / \\  / ___|| | | | |_ _|_   _|  / _ \\| | | |_   _|
 | |_| | / _ \\ \\___ \\| |_| |  | |  | |   | | | | | | | | |
 |  _  |/ ___ \\ ___) |  _  |  | |  | |   | |_| | |_| | | |
 |_| |_/_/   \\_\\____/|_| |_| |___| |_|    \\___/ \\___/  |_|
{C.RESET}
{C.MELT}  <<<====[ H.A.S.H  I.T  O.U.T ]====>>>{C.RESET}
{C.SLIME}  ||| d3c0d3r . r3v3rs3r . f1l3 r3bu1ld3r |||{C.RESET}
{C.DRIP}  >|> 5739o . v4.0.0 . github.com/RRSWSEC/Hash-It-Out <|<{C.RESET}
{C.ACID}  +======================================================+
  |  {C.YELLOW}for educational and authorized research use only{C.ACID}  |
  +======================================================+{C.RESET}
""")

def print_help():
    print(f"""
{C.TOXGRN}{C.BOLD}[ HASH IT OUT v3 :: USAGE ]{C.RESET}

{C.CYAN}USAGE:{C.RESET}
  hashitout [FLAGS] "<encoded_string>"
  hashitout [FLAGS] -f <file_path>
  hashitout                              {C.DIM}# drops into interactive shell{C.RESET}

{C.CYAN}INPUT:{C.RESET}
  {C.YELLOW}-f, --file <path>{C.RESET}     Analyze a file (text or binary)
  {C.YELLOW}-s, --string <str>{C.RESET}   Analyze an inline string
  {C.YELLOW}-o, --output <dir>{C.RESET}   Output directory  (default: ./output)

{C.CYAN}DECODERS:{C.RESET}
  {C.YELLOW}--all{C.RESET}               Run everything (default when no flag is set)
  {C.YELLOW}--rot{C.RESET}               ROT1-25, ROT47, ROT5, ROT18
  {C.YELLOW}--base{C.RESET}              Base2/8/10/16/32/32hex/32crockford/36/45/
                      58/58flickr/62/64/64url/64mime/85/ascii85/z85/91/92
  {C.YELLOW}--hex{C.RESET}               Hex, escaped \\x and %XX hex
  {C.YELLOW}--binary{C.RESET}            Binary (01 string) and Octal
  {C.YELLOW}--url{C.RESET}               URL encoding, double URL, HTML entities
  {C.YELLOW}--morse{C.RESET}             Morse code
  {C.YELLOW}--cipher{C.RESET}            Atbash, Vigenère, Affine, Bacon, Rail Fence,
                      Polybius, Tap Code, NATO phonetic, Leet speak
  {C.YELLOW}--xor{C.RESET}               Single-byte XOR (all 256) + common multi-byte keys
  {C.YELLOW}--misc{C.RESET}              Quoted-Printable, UUEncoding, Punycode
  {C.YELLOW}--stego{C.RESET}             LSB all 8 bit-planes, SNOW whitespace stego,
                      zero-width Unicode, PNG chunks, JPEG/ZIP comments,
                      embedded file scan (every offset), polyglot detect,
                      zlib stream extraction
  {C.YELLOW}--deep{C.RESET}              Everything in --stego + format-specific deep dives
  {C.YELLOW}--reverse{C.RESET}           Re-run all decoders on reversed input

{C.CYAN}OUTPUT:{C.RESET}
  {C.YELLOW}--savefile{C.RESET}          Save reconstructed binary files
  {C.YELLOW}--report{C.RESET}            Force save text report
  {C.YELLOW}--noreport{C.RESET}          Suppress auto report
  {C.YELLOW}--quiet{C.RESET}             No terminal output
  {C.YELLOW}--nocolor{C.RESET}           Disable ANSI colors

{C.CYAN}OTHER:{C.RESET}
  {C.YELLOW}--shell{C.RESET}             Interactive shell
  {C.YELLOW}--version{C.RESET}           Version info
  {C.YELLOW}--help, -h{C.RESET}          This screen

{C.CYAN}EXAMPLES:{C.RESET}
  {C.DIM}hashitout "SGVsbG8gV29ybGQ="
  hashitout --rot --base "VGVzdCBTdHJpbmc="
  hashitout --all -f suspicious.bin -o ./results
  hashitout --stego -f image.png
  hashitout --deep -f mystery.jpg
  hashitout --xor --hex "deadbeef"
  hashitout --shell{C.RESET}

{C.YELLOW}This tool targets reversible encodings only.{C.RESET}
{C.DIM}It does not crack one-way hashes (MD5, SHA, bcrypt, etc).
AI-assisted filtering: hashitout-ai (coming soon){C.RESET}

                                        {C.TOXGRN}St4y 1337.{C.RESET}
""")


def print_results(findings, source_label, input_size, verbose=True, nocolor=False, max_display=100):
    high   = [f for f in findings if f.confidence == 'HIGH']
    medium = [f for f in findings if f.confidence == 'MEDIUM']
    low    = [f for f in findings if f.confidence == 'LOW']

    bar = '─' * max(0, 44 - len(source_label))
    print(f"\n{C.CYAN}{C.BOLD}┌─[ RESULTS :: {source_label} ]{bar}┐{C.RESET}")
    print(f"  {C.WHITE}Input length     : {input_size}{C.RESET}")
    print(f"  {C.GREEN}High confidence  : {len(high)}{C.RESET}")
    print(f"  {C.YELLOW}Medium confidence: {len(medium)}{C.RESET}")
    print(f"  {C.DIM}Low confidence   : {len(low)}{C.RESET}")
    print(f"  {C.WHITE}Total            : {len(findings)}{C.RESET}")

    if not findings:
        print(f"\n  {C.RED}[!] No decodable patterns found.{C.RESET}")
        print(f"  {C.DIM}    May be encrypted, a true one-way hash, random data,{C.RESET}")
        print(f"  {C.DIM}    or an unsupported encoding format.{C.RESET}")
        return

    if not verbose:
        return

    if high:
        print(f"\n{C.GREEN}{C.BOLD}┌─[ HIGH CONFIDENCE ]{'═' * 52}┐{C.RESET}")
        for i, f in enumerate(high, 1):
            _print_finding(f, i)

    if medium:
        print(f"\n{C.YELLOW}{C.BOLD}┌─[ MEDIUM CONFIDENCE ]{'─' * 50}┐{C.RESET}")
        for i, f in enumerate(medium, 1):
            _print_finding(f, i + len(high))

    if low:
        print(f"\n{C.DIM}┌─[ LOW CONFIDENCE ]{'*' * 53}┐{C.RESET}")
        if len(low) <= 4:
            for i, f in enumerate(low, 1):
                _print_finding(f, i + len(high) + len(medium))
        else:
            print(f"  {C.DIM}({len(low)} low-confidence results  -  see report file){C.RESET}")


def _print_finding(f, index: int):
    conf_col = CONF_COLOR.get(f.confidence, C.WHITE)
    print(f"\n{C.CYAN}  [{index:03d}] {C.BOLD}{C.TOXGRN}{f.method}{C.RESET}")
    print(f"        {conf_col}Confidence : {f.confidence}{C.RESET}", end='')
    if f.filetype:
        print(f"  {C.GREEN}│ FILE: {f.filetype[1]} (.{f.filetype[0]}){C.RESET}", end='')
    print()
    if f.note:
        print(f"        {C.DIM}Note       : {f.note}{C.RESET}")
    if f.result_text:
        preview = f.result_text[:400]
        if len(f.result_text) > 400:
            preview += f'  {C.DIM}[...{len(f.result_text)} chars]{C.RESET}'
        print(f"        {C.WHITE}Output     :{C.RESET}")
        for line in preview.split('\n')[:10]:
            print(f"          {C.CYAN}│{C.RESET} {line}")
    elif f.result_bytes:
        print(f"        {C.WHITE}Output     :{C.RESET} {C.DIM}[binary] "
              f"{bytes_to_hex_display(f.result_bytes, 40)}{C.RESET}")


def print_file_saved(filepath: str, method: str, filetype: str):
    print(f"\n  {C.GREEN}{C.BOLD}[+] FILE REBUILT{C.RESET}")
    print(f"      {C.TOXGRN}Method   : {method}{C.RESET}")
    print(f"      {C.TOXGRN}Type     : {filetype}{C.RESET}")
    print(f"      {C.TOXGRN}Saved to : {filepath}{C.RESET}")


def generate_text_report(findings: list, source: str,
                          input_data: str, saved_files: list = None) -> str:
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = [
        '=' * 72,
        '  HASH IT OUT v3  -  ANALYSIS REPORT',
        f'  Generated : {ts}',
        f'  Source    : {source_label}',
        f'  Input Len : {len(input_data)} characters',
        '=' * 72,
        '',
        'INPUT (first 200 chars):',
        input_data[:200] + ('...' if len(input_data) > 200 else ''),
        '',
        '─' * 72,
        'SUMMARY:',
        f'  Total     : {len(findings)}',
        f'  HIGH      : {len([f for f in findings if f.confidence == "HIGH"])}',
        f'  MEDIUM    : {len([f for f in findings if f.confidence == "MEDIUM"])}',
        f'  LOW       : {len([f for f in findings if f.confidence == "LOW"])}',
        '',
    ]

    if saved_files:
        lines += ['─' * 72, 'REBUILT FILES:']
        for sf in saved_files:
            lines.append(f'  [REBUILT] {sf}')
        lines.append('')

    lines += ['─' * 72, 'DETAILED FINDINGS:', '']

    for i, f in enumerate(findings, 1):
        lines.append(f'[{i:03d}] Method     : {f.method}')
        lines.append(f'     Confidence: {f.confidence}')
        if f.filetype:
            lines.append(f'     File Type : {f.filetype[1]} (.{f.filetype[0]})')
        if f.note:
            lines.append(f'     Note      : {f.note}')
        if f.result_text:
            ratio = sum(1 for c in f.result_text if c in string.printable) / max(len(f.result_text), 1)
            if ratio > 0.75:
                lines.append('     Output    :')
                for line in f.result_text[:1000].split('\n'):
                    lines.append(f'       {line}')
                if len(f.result_text) > 1000:
                    lines.append(f'       ... [{len(f.result_text)} chars total]')
            else:
                lines.append('     Output    : [non-printable  -  see saved file]')
        elif f.result_bytes:
            lines.append(f'     Output    : [binary] {bytes_to_hex_display(f.result_bytes, 32)}')
        lines.append('')

    lines += [
        '─' * 72,
        'DECODING CHAIN:',
        '',
    ]
    successful = [f for f in findings if f.confidence in ('HIGH', 'MEDIUM')]
    if successful:
        for f in successful:
            lines.append(f'  Method     : {f.method}')
            if f.filetype:
                lines.append(f'  Result     : {f.filetype[1]}')
            lines.append(f'  Confidence : {f.confidence}')
            lines.append('')
    else:
        lines.append('  No high/medium confidence results.')

    lines += [
        '=' * 72,
        'Hash It Out v4.0.0   -   github.com/RRSWSEC/Hash-It-Out',
        '=' * 72,
    ]
    return '\n'.join(lines)


def save_report(report_text: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(output_dir, f'HIO_{ts}.txt')
    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write(report_text)
    return filepath


def save_decoded_file(data: bytes, output_dir: str, method: str,
                      ext: str, base_name: str = 'decoded') -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = method.replace('/', '_').replace(' ', '_').replace('→', 'to')[:40]
    filepath = os.path.join(output_dir, f'{base_name}_{safe}_{ts}.{ext}')
    with open(filepath, 'wb') as fh:
        fh.write(data)
    return filepath

def print_url_header(url, status, content_type, size, error=''):
    if error:
        print(f"  \033[91m[!] Fetch failed: {error}\033[0m"); return
    print(f"\033[96m[*] Status   : {status}\033[0m")
    print(f"\033[96m[*] Type     : {content_type}\033[0m")
    print(f"\033[96m[*] Size     : {size:,} bytes\033[0m")

def results_to_json(findings, source_label):
    import datetime
    return {'source': source_label, 'timestamp': datetime.datetime.now().isoformat(),
            'total': len(findings), 'findings': [
                {'method': f.method, 'confidence': f.confidence, 'note': f.note,
                 'result_text': f.result_text[:2000] if f.result_text else None}
                for f in findings]}

def save_csv_report(findings, source_label, output_dir):
    import csv, datetime, os, re
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f'hio_findings_{ts}.csv')
    with open(path, 'w', newline='', encoding='utf-8', errors='replace') as fh:
        w = csv.writer(fh)
        w.writerow(['confidence','method','source','note','result_preview'])
        for f in findings:
            w.writerow([f.confidence, f.method, f.source_label or source_label,
                        (f.note or '')[:200], (f.result_text or '')[:200]])
    return path

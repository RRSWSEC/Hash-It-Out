#!/usr/bin/env python3
"""
hashitout  -  Hash It Out v4.0.0
Elite decoder * reversing tool * stego scanner * URL content analyzer
github.com/RRSWSEC/Hash-It-Out
"""

import sys
import os
import argparse
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import AnalysisEngine, fetch_url, MAX_REPORT_STRING_LEN
from core.reporter import (
    print_banner, print_help, print_results,
    print_file_saved, print_url_header,
    generate_text_report, results_to_json,
    save_report, save_decoded_file, C,
)
from core.filetypes import detect_filetype

VERSION       = '4.0.0'
DISPLAY_DELAY = 2.0


def load_wordlist() -> set:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists', 'english.txt')
    words = set()
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.strip().lower()
                if w:
                    words.add(w)
    return words


def run_analysis(input_data, source_label, flags, output_dir, wordlist,
                 quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    if not quiet:
        print(f"\n{C.CYAN}[*] Input    : {C.WHITE}{source_label}{C.RESET}")
        print(f"{C.CYAN}[*] Length   : {C.WHITE}{len(input_data)} chars{C.RESET}")
        print(f"{C.CYAN}[*] Wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay:
        time.sleep(DISPLAY_DELAY)
    engine = AnalysisEngine(wordlist=wordlist, output_dir=output_dir,
                            verbose=True, flags=flags, max_depth=max_depth,
                            stegopw_wordlist=stegopw_wordlist)
    findings = engine.analyze_string(input_data, source_label)
    if not quiet:
        print_results(findings, source_label, len(input_data), verbose=True)
    saved_files = _save_findings(findings, flags, output_dir, source_label)
    _write_report(findings, source_label, input_data, saved_files,
                  flags, output_dir, save_json, quiet)


def run_from_file(filepath, flags, output_dir, wordlist,
                  quiet=False, nodelay=False, save_json=False,
                  max_depth=3, stegopw_wordlist=None):
    if not os.path.exists(filepath):
        print(f"  {C.RED}[!] File not found: {filepath}{C.RESET}")
        return
    size = os.path.getsize(filepath)
    if not quiet:
        print(f"\n{C.CYAN}[*] File     : {C.WHITE}{filepath}{C.RESET}")
        print(f"{C.CYAN}[*] Size     : {C.WHITE}{size:,} bytes{C.RESET}")
        print(f"{C.CYAN}[*] Depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] Wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay:
        time.sleep(DISPLAY_DELAY)
    try:
        with open(filepath, 'rb') as fh:
            raw_bytes = fh.read()
    except Exception as e:
        print(f"  {C.RED}[!] Cannot read file: {e}{C.RESET}")
        return
    engine = AnalysisEngine(wordlist=wordlist, output_dir=output_dir,
                            verbose=True, flags=flags, max_depth=max_depth,
                            stegopw_wordlist=stegopw_wordlist)
    source = os.path.basename(filepath)
    findings = engine.analyze_file(raw_bytes, source)
    if not quiet:
        print_results(findings, source, len(raw_bytes), verbose=True,
                      nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, output_dir, source)
    _write_report(findings, source, raw_bytes[:MAX_REPORT_STRING_LEN].decode('latin-1'),
                  saved_files, flags, output_dir, save_json, quiet)


def run_from_url(url, flags, output_dir, wordlist,
                 quiet=False, nodelay=False, save_json=False,
                 max_depth=3, stegopw_wordlist=None):
    if not quiet:
        print(f"\n{C.CYAN}[*] Fetching : {C.WHITE}{url}{C.RESET}")
    fetch = fetch_url(url)
    if not quiet:
        print_url_header(url=url, status=fetch.status,
                         content_type=fetch.content_type,
                         size=len(fetch.raw_bytes), error=fetch.error)
    if fetch.error:
        return
    if not quiet:
        print(f"{C.CYAN}[*] Binary   : {C.WHITE}{fetch.is_binary}{C.RESET}")
        if fetch.detected_type:
            print(f"{C.CYAN}[*] Detected : {C.WHITE}{fetch.detected_type[1]}{C.RESET}")
        print(f"{C.CYAN}[*] Depth    : {C.WHITE}{max_depth} level(s){C.RESET}")
        print(f"{C.CYAN}[*] Wordlist : {C.WHITE}{len(wordlist):,} words{C.RESET}")
    if not nodelay:
        time.sleep(DISPLAY_DELAY)
    engine = AnalysisEngine(wordlist=wordlist, output_dir=output_dir,
                            verbose=True, flags=flags, max_depth=max_depth,
                            stegopw_wordlist=stegopw_wordlist)
    findings = engine.analyze_url(url)
    source = f'URL:{url}'
    if not quiet:
        print_results(findings, url, len(fetch.raw_bytes), verbose=True,
                      nocolor=flags.get('nocolor', False))
    saved_files = _save_findings(findings, flags, output_dir, source)
    input_preview = (fetch.text if not fetch.is_binary else
                     fetch.raw_bytes[:MAX_REPORT_STRING_LEN].decode('latin-1'))
    _write_report(findings, source, input_preview, saved_files,
                  flags, output_dir, save_json, quiet)


def run_shell(flags, output_dir, wordlist, quiet=False, save_json=False,
              max_depth=3, stegopw_wordlist=None):
    print(f"\n{C.TOXGRN}{C.BOLD}  [ HASH IT OUT v4 :: INTERACTIVE SHELL ]{C.RESET}")
    print(f"  {C.DIM}commands: <string>  file <path>  url <url>  help  exit{C.RESET}\n")
    while True:
        try:
            raw = input(f"{C.TOXGRN}hio>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            continue
        cmd = raw.lower()
        if cmd in ('exit', 'quit', 'q', ':q', 'bye'):
            print(f"\n  {C.TOXGRN}St4y 1337.{C.RESET}\n")
            break
        elif cmd.startswith('file '):
            for p in raw[5:].strip().split():
                run_from_file(p, flags, output_dir, wordlist, quiet,
                              nodelay=True, save_json=save_json,
                              max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        elif cmd.startswith('url '):
            for u in raw[4:].strip().split():
                run_from_url(u, flags, output_dir, wordlist, quiet,
                             nodelay=True, save_json=save_json,
                             max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        elif cmd in ('help', '?'):
            print_help()
        elif cmd.startswith('http'):
            run_from_url(raw, flags, output_dir, wordlist, quiet,
                         nodelay=True, save_json=save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        else:
            run_analysis(raw, 'SHELL INPUT', flags, output_dir, wordlist,
                         quiet, nodelay=True, save_json=save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)


def _save_findings(findings, flags, output_dir, source_label):
    saved = []
    if not flags.get('savefile'):
        return saved
    for f in findings:
        if f.result_bytes and f.filetype and f.filetype[0]:
            try:
                base = source_label.replace('/', '_').replace(':', '_')[:30]
                fp = save_decoded_file(f.result_bytes, output_dir,
                                        f.method, f.filetype[0], base)
                saved.append(fp)
                print_file_saved(fp, f.method, f.filetype[1])
            except Exception as e:
                print(f"  {C.RED}[!] could not save: {e}{C.RESET}")
    return saved


def _write_report(findings, source_label, input_data, saved_files,
                  flags, output_dir, save_json, quiet):
    if flags.get('noreport'):
        return
    auto = any(f.confidence in ('HIGH', 'MEDIUM') for f in findings)
    if not (flags.get('report') or auto):
        return
    os.makedirs(output_dir, exist_ok=True)
    report_text = generate_text_report(findings, source_label,
                                        str(input_data), saved_files)
    report_path = save_report(report_text, output_dir)
    try:
        from core.reporter import save_csv_report
        csv_path = save_csv_report(findings, source_label, output_dir)
        if not quiet:
            print(f"\n  {C.GREEN}[+] csv saved: {csv_path}{C.RESET}")
    except Exception:
        pass
    if save_json:
        j = results_to_json(findings, source_label)
        jpath = report_path.replace('.txt', '.json')
        with open(jpath, 'w', encoding='utf-8') as fh:
            json.dump(j, fh, indent=2)
        if not quiet:
            print(f"  {C.GREEN}[+] json saved: {jpath}{C.RESET}")
    if not quiet:
        print(f"  {C.GREEN}[+] report saved: {report_path}{C.RESET}")


def build_parser():
    p = argparse.ArgumentParser(prog='hashitout', add_help=False)
    p.add_argument('-f', '--file', metavar='PATH', nargs='+')
    p.add_argument('-s', '--string', metavar='STRING')
    p.add_argument('-u', '--url', metavar='URL', nargs='+')
    p.add_argument('-o', '--output', metavar='DIR', default='./output')
    p.add_argument('input_string', nargs='?', default=None)
    for flag in ('all', 'rot', 'base', 'hex', 'binary', 'morse',
                 'cipher', 'xor', 'misc', 'stego', 'deep', 'reverse', 'verbose'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--depth', metavar='N', type=int, default=None)
    p.add_argument('--stegopw', metavar='WORDLIST')
    for flag in ('savefile', 'report', 'noreport', 'quiet', 'nocolor',
                 'json', 'nodelay', 'shell', 'version'):
        p.add_argument(f'--{flag}', action='store_true')
    p.add_argument('--help', '-h', action='store_true')
    return p


def main():
    parser = build_parser()
    args, extra = parser.parse_known_args()
    if extra and not args.input_string:
        args.input_string = ' '.join(extra)
    if args.nocolor:
        for attr in [a for a in dir(C) if not a.startswith('_') and isinstance(getattr(C, a), str)]:
            setattr(C, attr, '')
    if not args.quiet:
        print_banner()
    if args.version:
        print(f"  Hash It Out v{VERSION}")
        print(f"  github.com/RRSWSEC/Hash-It-Out\n")
        return
    if args.help:
        print_help()
        if not any([args.shell, args.file, args.string, args.url, args.input_string]):
            return
    flags = {k: getattr(args, k, False) for k in
             ('all', 'rot', 'base', 'hex', 'binary', 'morse',
              'cipher', 'xor', 'misc', 'stego', 'deep', 'reverse', 'verbose',
              'savefile', 'report', 'noreport')}
    run_all = flags.get('all') or not any(
        flags.get(k) for k in ('rot', 'base', 'hex', 'binary', 'morse',
                                'cipher', 'xor', 'misc', 'stego', 'deep'))
    flags['all'] = run_all
    if args.depth is not None:
        max_depth = max(1, min(50, args.depth))
    elif run_all and not args.quiet:
        max_depth = 3
    else:
        max_depth = 3
    stegopw_wordlist = getattr(args, 'stegopw', None)
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    wordlist = load_wordlist()
    quiet = args.quiet
    nodelay = args.nodelay
    save_json = args.json
    ran_something = False
    if args.file:
        for filepath in args.file:
            run_from_file(filepath, flags, output_dir, wordlist,
                          quiet, nodelay, save_json,
                          max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran_something = True
    if args.url:
        for url in args.url:
            run_from_url(url, flags, output_dir, wordlist,
                         quiet, nodelay, save_json,
                         max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran_something = True
    input_str = args.string or args.input_string
    if input_str:
        run_analysis(input_str, 'CLI INPUT', flags, output_dir, wordlist,
                     quiet, nodelay, save_json,
                     max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)
        ran_something = True
    if args.shell or not ran_something:
        run_shell(flags, output_dir, wordlist, quiet, save_json,
                  max_depth=max_depth, stegopw_wordlist=stegopw_wordlist)


if __name__ == '__main__':
    main()

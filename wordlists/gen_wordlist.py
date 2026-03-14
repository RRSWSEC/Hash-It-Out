#!/usr/bin/env python3
"""
Generate wordlists/english.txt
Pulls from system dictionary if available, falls back to built-in minimal set.
Run automatically by install.sh, or manually: python3 wordlists/gen_wordlist.py
"""

import os

SYSTEM_DICTS = [
    '/usr/share/dict/words',
    '/usr/share/dict/american-english',
    '/usr/share/dict/british-english',
    '/usr/share/dict/english',
    '/usr/share/dict/cracklib-small',
]

# Minimal fallback — used only if no system dict is present
FALLBACK = """
a able about above across after again age ago ahead air all allow also
although always am among an and another any are area around as ask at away
back bad base be became because become been before being below best better
between big both bring but by call came can case cause change children city
close code come comes could country cut data day days debug decode different
do does down during each early encode end enough error even ever every example
face fact family far feel few file find first flag follow for form found from
get give go good got great group grow had hand happen hard has hash have he
head help her here hidden him his home how however if important in into is it
its just keep know land large last learn leave let life light like line little
long look made make man many may me mean might miss more most much must my
name need never new next night no not now number of off often old on once only
open or other our out over own part people place plan point possible problem
program put real right run said same school seem set she should show side
since small so some something soon stand state still stop such sure take than
that the their them there thing think through time to together too try turn
under until up us use very want way we well went what when where while who
will with word work world would write year yet you young
hello world quick brown fox jumps over lazy dog secret message test answer
solution challenge ctf cipher admin root login pass user server client network
system computer base binary hex output input forward reverse found hidden
inside stego steganography flag decode encode hash bytes file type image audio
video archive packet exploit buffer overflow pwn kernel null pointer memory
format string race condition crypto hidden payload shellcode nmap scan port
reverse shell bind netcat socat python bash perl php ruby java compiled binary
executable library shared object symbol table section header segment offset
address virtual physical stack heap bss data text rodata got plt plt got
relocation dynamic linker loader symbol resolution lazy binding got overwrite
format specifier arbitrary write arbitrary read information leak
"""


def generate():
    words = set()
    source = None

    for path in SYSTEM_DICTS:
        if os.path.exists(path):
            source = path
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    w = line.strip().lower()
                    if 2 <= len(w) <= 25 and "'" not in w and w.isalpha():
                        words.add(w)
            break

    if not words:
        print("[!] No system dictionary found — using built-in fallback")
        for w in FALLBACK.split():
            w = w.strip().lower()
            if len(w) >= 2 and w.isalpha():
                words.add(w)
        source = 'built-in fallback'

    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'english.txt')

    with open(out_path, 'w', encoding='utf-8') as f:
        for w in sorted(words):
            f.write(w + '\n')

    print(f"[+] Wordlist : {len(words):,} words")
    print(f"[+] Source   : {source}")
    print(f"[+] Path     : {out_path}")


if __name__ == '__main__':
    generate()

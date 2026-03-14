#!/usr/bin/env python3
"""
hashitout — Hash It Out v4.0.0
Elite decoder · reversing tool · stego scanner · URL content analyzer
github.com/RRSWSEC/Hash-It-Out

Every input — strings, files, URLs — is analyzed forward AND reversed
through every known decoder, cipher, and steganographic technique.
URL content is fetched, typed by magic bytes, and routed through the same
full pipeline as local files and strings. Zero external dependencies.
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

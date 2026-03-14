"""
core/renderer.py — Hash It Out v4
ANSI terminal image renderer using Pillow + half-block characters.

Each character cell uses ▀ (upper half block) with two 256-color codes,
giving 2 pixel rows per terminal line. Targets ~72 columns wide.
Falls back to greyscale if 256-color not supported.
"""

import io
import os
import sys
from typing import Optional, Tuple


# ANSI helpers
def _fg(r: int, g: int, b: int) -> str:
    return f'\033[38;2;{r};{g};{b}m'


def _bg(r: int, g: int, b: int) -> str:
    return f'\033[48;2;{r};{g};{b}m'


RESET = '\033[0m'


def _ansi_256_fg(r: int, g: int, b: int) -> str:
    """True-color (24-bit) foreground."""
    return f'\033[38;2;{r};{g};{b}m'


def _ansi_256_bg(r: int, g: int, b: int) -> str:
    """True-color (24-bit) background."""
    return f'\033[48;2;{r};{g};{b}m'


def supports_truecolor() -> bool:
    """Check if terminal likely supports 24-bit colour."""
    colorterm = os.environ.get('COLORTERM', '').lower()
    if colorterm in ('truecolor', '24bit'):
        return True
    term = os.environ.get('TERM', '')
    return '256' in term or 'xterm' in term

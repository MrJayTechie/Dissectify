"""Entry point for `python -m macos_ir` and the `dissectify` console script."""

from __future__ import annotations

import os
import sys
import time
import random
import shutil


LOGO_RAW = [
    "     ____  _                     _   _  __",
    "    |  _ \\(_)___ ___  ___  ___| |_(_)/ _|_   _",
    "    | | | | / __/ __|/ _ \\/ __| __| | |_| | | |",
    "    | |_| | \\__ \\__ \\  __/ (__| |_| |  _| |_| |",
    "    |____/|_|___/___/\\___|\\___|\\__|_|_|  \\__, |",
    "                                          |___/",
]

GLITCH_CHARS = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`0123456789ABCDEFabcdef"
CYBER_CHARS = "01"

SUBTITLE = "     macOS Forensic Analysis Toolkit  v1.0"
AUTHOR = "     by Ali Jammal"
QUOTE = '     "Every artifact tells a story. Every byte holds a truth."'

BOOT_MESSAGES = [
    ("Initializing forensic engine", "green"),
    ("Loading 61 dissect plugins", "green"),
    ("Mapping 70 collector artifacts", "green"),
    ("Verifying artifact signatures", "green"),
    ("Starting Dissectify", "cyan"),
]


def _move_cursor_up(n: int) -> None:
    sys.stdout.write(f"\033[{n}A")


def _clear_line() -> None:
    sys.stdout.write("\033[2K\r")


def _color(text: str, code: str) -> str:
    colors = {
        "cyan": "\033[1;36m",
        "green": "\033[32m",
        "dim": "\033[2m",
        "bold": "\033[1m",
        "italic": "\033[3m",
        "red": "\033[31m",
        "yellow": "\033[33m",
        "magenta": "\033[35m",
    }
    return f"{colors.get(code, '')}{text}\033[0m"


def _decrypt_reveal(lines: list[str], iterations: int = 12, delay: float = 0.04) -> None:
    """Hollywood-style decryption effect — random chars resolve into the real text."""
    height = len(lines)
    max_width = max(len(l) for l in lines)

    # Start with all chars scrambled
    # Each position has a "lock frame" — the iteration at which it locks to the real char
    lock_frame = []
    for line in lines:
        row = []
        for j, ch in enumerate(line):
            if ch == " ":
                row.append(0)  # spaces lock immediately
            else:
                # Characters lock progressively left-to-right with some randomness
                row.append(random.randint(max(1, j // 4), iterations - 1))
        lock_frame.append(row)

    # Print placeholder lines
    for _ in range(height):
        print()
    _move_cursor_up(height)

    for frame in range(iterations):
        for i, line in enumerate(lines):
            rendered = []
            for j, ch in enumerate(line):
                if frame >= lock_frame[i][j]:
                    rendered.append(ch)
                else:
                    rendered.append(random.choice(GLITCH_CHARS))
            # Color: locked chars in cyan, unlocked in dim green
            output = ""
            for j, ch in enumerate(rendered):
                if frame >= lock_frame[i][j] and ch != " ":
                    output += _color(ch, "cyan")
                elif ch != " ":
                    output += _color(ch, "dim")
                else:
                    output += " "
            _clear_line()
            sys.stdout.write(output)
            if i < height - 1:
                sys.stdout.write("\n")

        sys.stdout.flush()
        _move_cursor_up(height - 1)
        time.sleep(delay)

    # Final: move cursor past the logo
    for i in range(height - 1):
        sys.stdout.write("\n")
    print()


def _scanner_line(text: str, color_code: str = "green") -> None:
    """Print a line with a scanning dot effect."""
    sys.stdout.write(f"  \033[2m{text}\033[0m")
    sys.stdout.flush()

    # Animated brackets
    frames = ["[    ]", "[.   ]", "[..  ]", "[... ]", "[....]", "[ ok ]"]
    for f in frames:
        time.sleep(random.uniform(0.06, 0.12))
        # Move to end and overwrite
        sys.stdout.write(f"\r  \033[2m{text}\033[0m  ")
        if f == "[ ok ]":
            sys.stdout.write(_color(f, color_code))
        else:
            sys.stdout.write(_color(f, "dim"))
        sys.stdout.flush()
    print()


def _type_text(text: str, style: str = "dim", delay: float = 0.012) -> None:
    for ch in text:
        sys.stdout.write(_color(ch, style))
        sys.stdout.flush()
        time.sleep(delay)
    print()


def _intro() -> None:
    if not sys.stdout.isatty() or "--no-intro" in sys.argv:
        return

    os.system("clear")
    print()

    # Decryption reveal of the logo
    _decrypt_reveal(LOGO_RAW, iterations=14, delay=0.045)

    # Type out the subtitle
    _type_text(SUBTITLE, style="dim", delay=0.012)
    _type_text(AUTHOR, style="dim", delay=0.015)
    print()
    _type_text(QUOTE, style="italic", delay=0.012)
    print()

    # Boot sequence with scanner effect
    for msg, col in BOOT_MESSAGES:
        _scanner_line(msg, col)

    print()
    time.sleep(0.2)


def main():
    _intro()

    from macos_ir.app import MacOSIRApp
    app = MacOSIRApp()
    app.run()


if __name__ == "__main__":
    main()

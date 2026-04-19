#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# Dissectify — macOS Forensic Analysis Toolkit
# by Ali Jammal
#
# Double-click to launch. First run installs everything automatically.
# ──────────────────────────────────────────────────────────────────────────────

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

clear
echo ""
echo "  ┌─────────────────────────────────────────────┐"
echo "  │         Dissectify - Launcher                │"
echo "  │    macOS Forensic Analysis Toolkit           │"
echo "  │    by Ali Jammal                             │"
echo "  └─────────────────────────────────────────────┘"
echo ""

# ── Step 1: Check for Python 3.10+ ──

PYTHON=""
for p in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$p" &>/dev/null; then
        ver=$("$p" -c "import sys; print(sys.version_info >= (3,10))" 2>/dev/null)
        if [ "$ver" = "True" ]; then
            PYTHON="$p"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  ✗ Python 3.10+ is required but not found."
    echo ""
    echo "  To install Python:"
    echo ""
    echo "    Option 1 (recommended):"
    echo "      Download from https://www.python.org/downloads/macos/"
    echo "      Install the macOS universal installer (.pkg)"
    echo ""
    echo "    Option 2 (Homebrew):"
    echo "      /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    echo "      brew install python@3.12"
    echo ""
    echo "    Option 3 (Xcode Command Line Tools):"
    echo "      xcode-select --install"
    echo "      (installs Python 3, but may be older than 3.10)"
    echo ""
    echo "  After installing, double-click Dissectify.command again."
    echo ""
    read -p "  Press Enter to close..."
    exit 1
fi

PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
echo "  ✓ Python $PYVER found ($PYTHON)"

# ── Step 2: Check for git (needed for plugin/collector updates) ──

if command -v git &>/dev/null; then
    echo "  ✓ git found ($(git --version | cut -d' ' -f3))"
else
    echo "  ! git not found — Update Plugins/Collectors buttons won't work"
    echo "    Install with: xcode-select --install"
fi

# ── Step 3: Create venv and install on first run ──

if [ ! -d ".venv" ]; then
    echo ""
    echo "  ── First-time setup ──────────────────────────"
    echo ""

    echo "  [1/3] Creating virtual environment..."
    $PYTHON -m venv .venv
    if [ $? -ne 0 ]; then
        echo ""
        echo "  ✗ Failed to create virtual environment."
        echo "    Try: $PYTHON -m ensurepip --upgrade"
        echo ""
        read -p "  Press Enter to close..."
        exit 1
    fi

    echo "  [2/3] Upgrading pip..."
    .venv/bin/pip install --quiet --upgrade pip setuptools

    echo "  [3/3] Installing Dissectify + dependencies..."
    echo "         (dissect.target, textual, openpyxl — this takes ~2 minutes)"
    echo ""
    .venv/bin/pip install -e . 2>&1 | while read line; do
        # Show progress dots
        printf "."
    done
    echo ""

    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo ""
        echo "  ✗ Installation failed."
        echo ""
        echo "  Common fixes:"
        echo "    • Check your internet connection"
        echo "    • Try: .venv/bin/pip install -e . (to see the full error)"
        echo "    • On older macOS: xcode-select --install (for C compiler)"
        echo ""
        read -p "  Press Enter to close..."
        exit 1
    fi

    echo ""
    echo "  ✓ Setup complete!"
    echo ""
fi

# ── Step 4: Verify installation is intact ──

if [ ! -f ".venv/bin/dissectify" ]; then
    echo "  ! Entry point missing — reinstalling..."
    .venv/bin/pip install --quiet -e .
fi

# ── Launch ──

echo "  Launching Dissectify..."
echo ""
exec .venv/bin/dissectify "$@"

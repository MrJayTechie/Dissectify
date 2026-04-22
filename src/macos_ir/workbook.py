"""Plugin runner and XLSX workbook writer.

Invokes dissect plugin functions against a target and writes a multi-sheet
XLSX workbook with a summary sheet plus one sheet per artifact.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# ──────────────────────────────────────────────────────────────────────────────
# Target resolution
# ──────────────────────────────────────────────────────────────────────────────

DISSECT_PSEUDO_TARGETS = {"local"}


def resolve_target(collection_dir: str) -> str:
    """Resolve the target path (uploads/auto/) from the collection dir."""
    if collection_dir in DISSECT_PSEUDO_TARGETS:
        return collection_dir
    p = Path(collection_dir)
    if (p / "uploads" / "auto").is_dir():
        return str(p / "uploads" / "auto")
    if p.name == "auto" and (p / "Users").is_dir():
        return str(p)
    if (p / "auto").is_dir():
        return str(p / "auto")
    return str(p)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin runner
# ──────────────────────────────────────────────────────────────────────────────

def run_function(
    func: str,
    target: str,
    plugin_path: str,
    timeout: int = 600,
    progress_cb: Callable[[int], None] | None = None,
) -> tuple[list[dict] | None, str | None]:
    """Invoke dissect for one function, streaming records line-by-line.

    Returns (records, err). Uses an IDLE timeout rather than wall-clock
    so long-running plugins keep going as long as they produce output.
    """
    cmd = [
        sys.executable, "-m", "dissect.target.tools.query",
        "--plugin-path", plugin_path,
        "-f", func,
        target, "-j",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as e:
        return [], f"spawn failed: {e}"

    records: list[dict] = []
    last_activity = time.monotonic()
    timed_out = False

    import selectors
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)

    try:
        while True:
            events = sel.select(timeout=1.0)
            if events:
                line = proc.stdout.readline()
                if not line:
                    break
                last_activity = time.monotonic()
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict) or obj.get("_type") == "recorddescriptor":
                    continue
                records.append(obj)
                if progress_cb and len(records) % 500 == 0:
                    progress_cb(len(records))
            else:
                if time.monotonic() - last_activity > timeout:
                    timed_out = True
                    break
                if proc.poll() is not None:
                    tail = proc.stdout.read()
                    for tl in (tail.splitlines() if tail else ()):
                        tl = tl.strip()
                        if not tl:
                            continue
                        try:
                            obj = json.loads(tl)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(obj, dict) or obj.get("_type") == "recorddescriptor":
                            continue
                        records.append(obj)
                    break
    finally:
        sel.close()

    if timed_out:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        return None, "timeout"

    proc.wait()
    if proc.returncode != 0:
        err = (proc.stderr.read() or "").strip() if proc.stderr else ""
        if "Unsupported plugin" in err or "has no function" in err:
            return [], "incompat"
        if not records:
            return [], err.split("\n")[0][:200] if err else f"exit {proc.returncode}"
    return records, None


# ──────────────────────────────────────────────────────────────────────────────
# XLSX output
# ──────────────────────────────────────────────────────────────────────────────

DISSECT_INTERNAL_FIELDS = {
    "_type", "_classification", "_generated", "_version",
    "_recorddescriptor", "_source", "_classname", "_desc",
}

_INVALID_SHEET_CHARS = re.compile(r"[:\\/?*\[\]]")
_XLSX_ILLEGAL_RE = re.compile(r"[\000-\010\013\014\016-\037]")


def _safe_sheet_name(name: str, used: set[str]) -> str:
    cleaned = _INVALID_SHEET_CHARS.sub("_", name)[:31]
    base = cleaned or "sheet"
    candidate = base
    n = 2
    while candidate in used:
        suffix = f"~{n}"
        candidate = base[: 31 - len(suffix)] + suffix
        n += 1
    used.add(candidate)
    return candidate


def _record_columns(records: list[dict]) -> list[str]:
    seen: list[str] = []
    for rec in records:
        for k in rec:
            if k not in DISSECT_INTERNAL_FIELDS and k not in seen:
                seen.append(k)
    return seen


def _scrub(s: str) -> str:
    s = _XLSX_ILLEGAL_RE.sub("", s)
    if len(s) > 32760:
        s = s[:32757] + "..."
    return s


def _coerce_cell(v):
    if v is None:
        return ""
    if isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        return _scrub(v)
    if isinstance(v, (list, tuple)):
        return _scrub(", ".join(str(x) for x in v))
    if isinstance(v, dict):
        return _scrub(json.dumps(v, default=str))
    return _scrub(str(v))


# Cap per sheet at 900,000 rows — xlsx hard limit is 1,048,576 but leaving
# headroom avoids off-by-one surprises. Sheets exceeding this split into
# <sheetname>, <sheetname> (2), <sheetname> (3), ...
_MAX_ROWS_PER_SHEET = 900_000


def write_xlsx(
    per_source: list[tuple],
    all_records: list[tuple[str, list[dict]]],
    path: str,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> None:
    """Write a multi-sheet workbook: Summary + one sheet per function.

    Uses xlsxwriter with constant_memory=True — rows stream straight to
    disk without being held in RAM. 2-3x faster than openpyxl write_only
    and keeps peak RAM in the tens of MB even on million-row sheets.

    Auto-splits any artifact with more than 900,000 rows into numbered
    sibling sheets so the xlsx 1,048,576-row limit never causes silent
    truncation on big datasets (FSEvents, unified log).

    progress_cb(current, total, label): called before each sheet write
    and before the final file close. `total` covers the Summary + all
    (possibly split) per-artifact sheets + the final close step.
    """
    import xlsxwriter

    wb = xlsxwriter.Workbook(path, {
        "constant_memory": True,
        "default_date_format": "yyyy-mm-dd hh:mm:ss",
        "strings_to_numbers": False,
        "strings_to_formulas": False,
        "strings_to_urls": False,
    })

    header_fmt = wb.add_format({
        "bold": True,
        "font_color": "#FFFFFF",
        "bg_color": "#2F5496",
        "align": "left",
        "valign": "top",
    })

    def _write_header(ws, columns):
        for col_idx, col in enumerate(columns):
            ws.write(0, col_idx, col, header_fmt)
        ws.freeze_panes(1, 0)

    def _coerce_fast(v):
        # Fastest path: strings and None dominate; skip isinstance cascade
        if v is None:
            return ""
        t = type(v)
        if t is str:
            return _scrub(v)
        if t is bool or t is int or t is float:
            return v
        return _coerce_cell(v)

    def _write_rows(ws, columns, rows_iter, start_row=1):
        row_idx = start_row
        for rec in rows_iter:
            for col_idx, col in enumerate(columns):
                ws.write(row_idx, col_idx, _coerce_fast(rec.get(col)))
            row_idx += 1
        return row_idx

    used: set[str] = set()
    non_empty = [(f, r) for f, r in all_records if r]

    # Count expected sheets (including splits) for accurate progress total
    def _sheet_count_for(records):
        n = len(records)
        if n == 0:
            return 0
        return max(1, -(-n // _MAX_ROWS_PER_SHEET))  # ceil div

    total_sheets = 1 + sum(_sheet_count_for(r) for _, r in non_empty)
    total_steps = total_sheets + 1  # sheets + close
    step = 0

    # Summary sheet
    step += 1
    if progress_cb:
        progress_cb(step, total_steps, "Writing Summary sheet")
    ws = wb.add_worksheet(_safe_sheet_name("Summary", used))
    summary_cols = ["function", "category", "records", "status"]
    _write_header(ws, summary_cols)
    summary_rows = [
        {"function": p[0], "category": p[1], "records": p[2], "status": p[3] or "ok"}
        for p in per_source
    ]
    _write_rows(ws, summary_cols, summary_rows)

    # Per-artifact sheets, split if > _MAX_ROWS_PER_SHEET
    for func, records in non_empty:
        cols = _record_columns(records)
        n = len(records)
        shards = _sheet_count_for(records)

        for shard_idx in range(shards):
            step += 1
            start = shard_idx * _MAX_ROWS_PER_SHEET
            end = min(start + _MAX_ROWS_PER_SHEET, n)
            shard_records = records[start:end]

            base = func if shards == 1 else f"{func} ({shard_idx + 1})"
            sheet_name = _safe_sheet_name(base, used)

            if progress_cb:
                suffix = "" if shards == 1 else f"  [part {shard_idx + 1}/{shards}]"
                progress_cb(step, total_steps,
                    f"Writing sheet: {sheet_name} ({len(shard_records):,} rows){suffix}")

            ws = wb.add_worksheet(sheet_name)
            _write_header(ws, cols)
            _write_rows(ws, cols, shard_records)

    step += 1
    if progress_cb:
        progress_cb(step, total_steps, f"Saving {Path(path).name} (flushing to disk)")
    wb.close()

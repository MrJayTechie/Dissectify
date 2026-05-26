"""Apple Shortcuts (App Intents) library plugin.

``~/Library/Shortcuts/ToolKit/Tools-prod.v*-*.sqlite`` is the system-wide
catalog of every Shortcut / App Intent the device knows how to run —
both Apple's built-ins and third-party app contributions. Includes the
``Tools`` table (the actual shortcuts) and ``Categories``, ``Search
Keywords``, and per-tool localisations.
"""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(v):
    if v is None:
        return None
    try:
        return COCOA_EPOCH + timedelta(seconds=float(v))
    except (OSError, OverflowError, ValueError, TypeError):
        return None


ShortcutToolRecord = TargetRecordDescriptor(
    "macos/shortcuts/tool",
    [
        ("string", "identifier"),
        ("string", "name"),
        ("string", "subtitle"),
        ("string", "bundle_id"),
        ("string", "category"),
        ("string", "language"),
        ("path", "source"),
    ],
)


class AppleShortcutsPlugin(Plugin):
    """Parse the Apple Shortcuts toolkit catalog."""

    __namespace__ = "shortcuts"

    GLOB = "Users/*/Library/Shortcuts/ToolKit/Tools-prod.v*-*.sqlite"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Shortcuts toolkit found")

    def _open(self, db_path):
        with db_path.open("rb") as fh:
            data = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(data)
        tmp.flush()
        for suffix in ("-wal", "-shm"):
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())
        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=ShortcutToolRecord)
    def tools(self) -> Iterator[ShortcutToolRecord]:
        """One record per shortcut / App Intent in the catalog."""
        for db_path in self._db_paths:
            try:
                yield from self._parse(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Shortcuts %s: %s", db_path, e)

    def _parse(self, db_path):
        conn, tmp = self._open(db_path)
        try:
            cur = conn.cursor()
            tables = {r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            if "Tools" not in tables:
                return

            # The Tools table only holds the toolkit identifier + tool type;
            # human-readable name + description come from ToolLocalizations
            # (one row per locale) and the source container metadata
            # (bundleIdentifier, teamId, version) from ContainerMetadata.
            has_loc = "ToolLocalizations" in tables
            has_meta = "ContainerMetadata" in tables

            select = [
                "t.id AS ident",
                "t.toolType AS tool_type",
                ("loc.name" if has_loc else "''") + " AS name",
                ("loc.descriptionSummary" if has_loc else "''") + " AS sub",
                ("loc.locale" if has_loc else "''") + " AS locale",
                ("cm.id" if has_meta else "''") + " AS bundle",
            ]
            joins = []
            if has_loc:
                joins.append(
                    "LEFT JOIN ToolLocalizations loc ON loc.toolId = t.rowId "
                    "AND loc.locale = 'en'"
                )
            if has_meta:
                joins.append(
                    "LEFT JOIN ContainerMetadata cm ON cm.rowId = t.sourceContainerId"
                )

            query = (
                f"SELECT {', '.join(select)} FROM Tools t "  # noqa: S608
                + " ".join(joins)
            )
            cur.execute(query)
            for row in cur:
                yield ShortcutToolRecord(
                    identifier=str(row["ident"] or ""),
                    name=row["name"] or "",
                    subtitle=row["sub"] or "",
                    bundle_id=row["bundle"] or "",
                    category=str(row["tool_type"] or ""),
                    language=row["locale"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

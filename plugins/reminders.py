"""Apple Reminders plugin.

Reads the Core Data store under
``~/Library/Group Containers/group.com.apple.reminders/Container_v1/Stores/``.
Each Stores directory contains one ``Data-<UUID>.sqlite`` per CloudKit zone
plus a ``Data-local.sqlite`` for the local-only account. The schema is the
standard Core Data Z-prefix layout (``ZREMCDSAVEDREMINDER`` holds the
reminder entries, ``ZREMCDLISTBASE``-style tables hold list metadata).
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


def _cocoa_ts(value):
    if value is None:
        return None
    try:
        return COCOA_EPOCH + timedelta(seconds=float(value))
    except (OSError, OverflowError, ValueError, TypeError):
        return None


ReminderRecord = TargetRecordDescriptor(
    "macos/reminders/entry",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("datetime", "ts_due"),
        ("datetime", "ts_completed"),
        ("string", "title"),
        ("string", "notes"),
        ("string", "list_id"),
        ("varint", "priority"),
        ("varint", "completed"),
        ("path", "source"),
    ],
)


class AppleRemindersPlugin(Plugin):
    """Parse the Core Data stores under
    ``~/Library/Group Containers/group.com.apple.reminders/``."""

    __namespace__ = "reminders"

    GLOBS = [
        "Users/*/Library/Group Containers/group.com.apple.reminders/Container_v1/Stores/Data-*.sqlite",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        for pat in self.GLOBS:
            self._db_paths.extend(self.target.fs.path("/").glob(pat))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Reminders database found")

    def _open_db(self, db_path):
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

    @export(record=ReminderRecord)
    def entries(self) -> Iterator[ReminderRecord]:
        """Yield one record per saved reminder. Schema is Core Data Z-prefix —
        we probe the actual columns and gracefully tolerate Apple schema
        revisions."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_db(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Reminders DB %s: %s", db_path, e)

    def _parse_db(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cur = conn.cursor()
            tables = {r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            # Apple uses ZREMCDSAVEDREMINDER on modern macOS; some older builds
            # used ZREMCDREMINDER (no SAVED). Pick whichever exists.
            table = None
            for cand in ("ZREMCDSAVEDREMINDER", "ZREMCDREMINDER"):
                if cand in tables:
                    table = cand
                    break
            if table is None:
                return

            cols = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}

            def col(*names):
                for n in names:
                    if n in cols:
                        return n
                return None

            title_col = col("ZTITLE1", "ZTITLE", "ZSUMMARY")
            notes_col = col("ZNOTES1", "ZNOTES")
            created_col = col("ZCREATIONDATE", "ZCREATEDDATE")
            modified_col = col("ZLASTMODIFIEDDATE", "ZMODIFIEDDATE")
            due_col = col("ZDUEDATE")
            done_col = col("ZCOMPLETIONDATE", "ZCOMPLETEDDATE")
            list_col = col("ZLISTBASE", "ZLISTID")
            prio_col = col("ZPRIORITY")
            comp_col = col("ZCOMPLETED", "ZISCOMPLETED")

            select = [
                f"{title_col or 'NULL'} AS title",
                f"{notes_col or 'NULL'} AS notes",
                f"{created_col or 'NULL'} AS ts_created",
                f"{modified_col or 'NULL'} AS ts_modified",
                f"{due_col or 'NULL'} AS ts_due",
                f"{done_col or 'NULL'} AS ts_done",
                f"{list_col or 'NULL'} AS list_id",
                f"{prio_col or '0'} AS priority",
                f"{comp_col or '0'} AS completed",
            ]
            cur.execute(f"SELECT {', '.join(select)} FROM {table}")  # noqa: S608
            for row in cur:
                yield ReminderRecord(
                    ts_created=_cocoa_ts(row["ts_created"]),
                    ts_modified=_cocoa_ts(row["ts_modified"]),
                    ts_due=_cocoa_ts(row["ts_due"]),
                    ts_completed=_cocoa_ts(row["ts_done"]),
                    title=row["title"] or "",
                    notes=row["notes"] or "",
                    list_id=str(row["list_id"] or ""),
                    priority=row["priority"] or 0,
                    completed=row["completed"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

"""macOS authorization rules plugin.

``/private/var/db/auth.db`` holds the authorization-rights ruleset
(``rules`` table). Each row is a named right (``com.apple.runAsRoot``,
``system.privilege.taskport``, …) plus its requirement (``allow``, ``deny``,
``authenticate-session-owner``, mechanism chains, etc.). Useful for spotting
locally-modified privilege rules or comparing against a known-good baseline.
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


AuthRuleRecord = TargetRecordDescriptor(
    "macos/auth/rule",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("string", "name"),
        ("string", "rule_class"),
        ("string", "kofn"),
        ("string", "comment"),
        ("varint", "timeout"),
        ("varint", "tries"),
        ("varint", "shared"),
        ("varint", "session_owner"),
        ("path", "source"),
    ],
)


class MacOSAuthPlugin(Plugin):
    """Parse ``/private/var/db/auth.db``."""

    __namespace__ = "auth"

    DB_PATHS = ["private/var/db/auth.db"]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = [
            p for p in (self.target.fs.path("/") / x for x in self.DB_PATHS) if p.exists()
        ]

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No auth.db found")

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

    @export(record=AuthRuleRecord)
    def rules(self) -> Iterator[AuthRuleRecord]:
        """One record per authorization right defined in auth.db."""
        for db_path in self._db_paths:
            try:
                yield from self._parse(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing auth.db %s: %s", db_path, e)

    def _parse(self, db_path):
        conn, tmp = self._open(db_path)
        try:
            cur = conn.cursor()
            cols = {r[1] for r in cur.execute("PRAGMA table_info(rules)").fetchall()}

            def col(*names):
                for n in names:
                    if n in cols:
                        return n
                return None

            select = ", ".join(filter(None, [
                col("name"),
                f"{col('class')} AS rule_class" if col("class") else "'' AS rule_class",
                col("kofn"),
                col("comment"),
                col("timeout"),
                col("tries"),
                col("shared"),
                col("session_owner"),
                col("created"),
                col("modified"),
            ]))
            cur.execute(f"SELECT {select} FROM rules")  # noqa: S608
            for row in cur:
                yield AuthRuleRecord(
                    ts_created=_cocoa_ts(row["created"]) if "created" in row.keys() else None,
                    ts_modified=_cocoa_ts(row["modified"]) if "modified" in row.keys() else None,
                    name=row["name"] or "",
                    rule_class=str(row["rule_class"] or ""),
                    kofn=str(row["kofn"] or "") if "kofn" in row.keys() else "",
                    comment=row["comment"] if "comment" in row.keys() else "",
                    timeout=row["timeout"] or 0 if "timeout" in row.keys() else 0,
                    tries=row["tries"] or 0 if "tries" in row.keys() else 0,
                    shared=row["shared"] or 0 if "shared" in row.keys() else 0,
                    session_owner=row["session_owner"] or 0
                    if "session_owner" in row.keys() else 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

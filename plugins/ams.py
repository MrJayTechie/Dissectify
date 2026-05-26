"""Apple Media Services Engagement plugin.

``~/Library/AppleMediaServices/Engagement/journeys/database/app.db`` and
``…/analytics/database/app.db`` cache the user's App Store, Apple Music,
Books, TV, and News engagement events. The ``content`` table stores
opaque BLOBs keyed by ``cacheKey`` with a ``lastModified`` timestamp —
useful as a per-store activity heartbeat.
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
    """AMS uses CFAbsoluteTime (seconds since 2001-01-01) in lastModified."""
    if v is None:
        return None
    try:
        return COCOA_EPOCH + timedelta(seconds=float(v))
    except (OSError, OverflowError, ValueError, TypeError):
        return None


AMSContentRecord = TargetRecordDescriptor(
    "macos/ams/content",
    [
        ("datetime", "ts_modified"),
        ("string", "cache_key"),
        ("string", "version"),
        ("string", "task_identifier"),
        ("varint", "state"),
        ("string", "batch_keys"),
        ("string", "metadata"),
        ("path", "source"),
    ],
)


class AppleMediaServicesPlugin(Plugin):
    """Parse the AppleMediaServices engagement caches (journeys + analytics)."""

    __namespace__ = "ams"

    GLOB = (
        "Users/*/Library/AppleMediaServices/Engagement/journeys/database/app.db",
        "Users/*/Library/AppleMediaServices/Engagement/analytics/database/app.db",
    )

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        for pat in self.GLOB:
            self._db_paths.extend(self.target.fs.path("/").glob(pat))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No AppleMediaServices engagement DB found")

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

    @export(record=AMSContentRecord)
    def content(self) -> Iterator[AMSContentRecord]:
        """One record per AMS engagement cache entry (App Store / Music / Books / News)."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT cacheKey, version, taskIdentifier, state, "
                        "lastModified, batchKeys, metadata FROM content"
                    )
                except sqlite3.OperationalError:
                    continue
                for row in cur:
                    yield AMSContentRecord(
                        ts_modified=_cocoa_ts(row["lastModified"]),
                        cache_key=row["cacheKey"] or "",
                        version=row["version"] or "",
                        task_identifier=row["taskIdentifier"] or "",
                        state=row["state"] or 0,
                        batch_keys=row["batchKeys"] or "",
                        metadata=str(row["metadata"] or "")[:500],
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

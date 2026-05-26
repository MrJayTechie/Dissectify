"""Apple StatusKit (Focus statuses) plugin.

``~/Library/StatusKit/database/statuskit-cloud.db`` is the Core Data
store for iOS-style **Focus statuses** that the user has published or
received via CloudKit. Each channel (``ZCHANNEL``) is a sharing scope;
each published status (``ZPUBLISHEDLOCALSTATUS``) is what the user told
contacts ("I'm driving", "Do Not Disturb is on", etc.).
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


FocusChannelRecord = TargetRecordDescriptor(
    "macos/statuskit/channel",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("string", "uuid"),
        ("string", "channel_type"),
        ("varint", "muted"),
        ("path", "source"),
    ],
)

FocusStatusRecord = TargetRecordDescriptor(
    "macos/statuskit/status",
    [
        ("datetime", "ts_published"),
        ("datetime", "ts_expires"),
        ("string", "uuid"),
        ("string", "mode_name"),
        ("string", "delivery_state"),
        ("path", "source"),
    ],
)


class AppleStatusKitPlugin(Plugin):
    """Parse ``~/Library/StatusKit/database/statuskit-cloud.db``."""

    __namespace__ = "statuskit"

    GLOB = "Users/*/Library/StatusKit/database/statuskit-cloud.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No StatusKit database found")

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

    @export(record=FocusChannelRecord)
    def channels(self) -> Iterator[FocusChannelRecord]:
        """One record per published Focus channel."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT ZUUID AS uuid, ZCHANNELTYPE AS ctype, "
                        "ZCREATIONDATE AS ts_created, "
                        "ZMODIFICATIONDATE AS ts_modified, "
                        "ZMUTED AS muted FROM ZCHANNEL"
                    )
                except sqlite3.OperationalError:
                    continue
                for row in cur:
                    yield FocusChannelRecord(
                        ts_created=_cocoa_ts(row["ts_created"]),
                        ts_modified=_cocoa_ts(row["ts_modified"]),
                        uuid=row["uuid"] or "",
                        channel_type=str(row["ctype"] or ""),
                        muted=row["muted"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

    @export(record=FocusStatusRecord)
    def statuses(self) -> Iterator[FocusStatusRecord]:
        """One record per published local status."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT ZUUID, ZMODENAME, ZPUBLISHDATE, ZEXPIRYDATE, "
                        "ZDELIVERYSTATE FROM ZPUBLISHEDLOCALSTATUS"
                    )
                except sqlite3.OperationalError:
                    continue
                for row in cur:
                    yield FocusStatusRecord(
                        ts_published=_cocoa_ts(row["ZPUBLISHDATE"]),
                        ts_expires=_cocoa_ts(row["ZEXPIRYDATE"]),
                        uuid=row["ZUUID"] or "",
                        mode_name=row["ZMODENAME"] or "",
                        delivery_state=str(row["ZDELIVERYSTATE"] or ""),
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

"""macOS Quarantine Events plugin.

LaunchServices records a row in ``com.apple.LaunchServices.QuarantineEventsV2``
for every file the OS quarantines — typically downloads from a browser, AirDrop
receipts, attachments saved from Messages/Mail, and files received from
external apps. The row captures the source URL, the agent that delivered the
file (Safari, Chrome, MobileSMS, sharingd, etc.), and a timestamp.

This is one of the highest-signal artifacts in macOS DFIR for "where did this
file come from"; correlating the quarantine event with file paths on disk
recovers full provenance.
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
    """Convert Cocoa epoch seconds (with subsecond precision) to a datetime."""
    if value is None:
        return None
    try:
        return COCOA_EPOCH + timedelta(seconds=float(value))
    except (OSError, OverflowError, ValueError, TypeError):
        return None


QuarantineEventRecord = TargetRecordDescriptor(
    "macos/quarantine/event",
    [
        ("datetime", "ts"),
        ("string", "event_id"),
        ("string", "agent_bundle_id"),
        ("string", "agent_name"),
        ("string", "type_number"),
        ("string", "sender_name"),
        ("string", "sender_address"),
        ("string", "origin_title"),
        ("string", "origin_url"),
        ("string", "data_url"),
        ("path", "source"),
    ],
)


class MacOSQuarantinePlugin(Plugin):
    """Parse the macOS LaunchServices quarantine database.

    Location:
        ``~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2``
    """

    __namespace__ = "quarantine"

    DB_GLOB = "Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Quarantine database found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()
        for suffix in ("-wal", "-shm"):
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())
        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=QuarantineEventRecord)
    def events(self) -> Iterator[QuarantineEventRecord]:
        """Yield one record per quarantine event (downloads + AirDrop +
        attachments). Timestamps are Cocoa-epoch REAL values; we convert
        to UTC datetimes."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_db(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing quarantine DB %s: %s", db_path, e)

    def _parse_db(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT LSQuarantineEventIdentifier,
                       LSQuarantineTimeStamp,
                       LSQuarantineAgentBundleIdentifier,
                       LSQuarantineAgentName,
                       LSQuarantineTypeNumber,
                       LSQuarantineSenderName,
                       LSQuarantineSenderAddress,
                       LSQuarantineOriginTitle,
                       LSQuarantineOriginURLString,
                       LSQuarantineDataURLString
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC
                """,
            )
            for row in cursor:
                yield QuarantineEventRecord(
                    ts=_cocoa_ts(row["LSQuarantineTimeStamp"]),
                    event_id=row["LSQuarantineEventIdentifier"] or "",
                    agent_bundle_id=row["LSQuarantineAgentBundleIdentifier"] or "",
                    agent_name=row["LSQuarantineAgentName"] or "",
                    type_number=str(row["LSQuarantineTypeNumber"] or ""),
                    sender_name=row["LSQuarantineSenderName"] or "",
                    sender_address=row["LSQuarantineSenderAddress"] or "",
                    origin_title=row["LSQuarantineOriginTitle"] or "",
                    origin_url=row["LSQuarantineOriginURLString"] or "",
                    data_url=row["LSQuarantineDataURLString"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

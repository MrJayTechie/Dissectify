"""Time Machine plugin.

Reads ``/Library/Preferences/com.apple.TimeMachine.plist`` for the backup
destinations the user has configured, the schedule, and the most recent
backup timestamps (per-destination). Useful both as anti-forensics
("user just disabled backups") and as a pointer to where additional
copies of the user's data live.
"""

from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


def _dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


TimeMachineDestRecord = TargetRecordDescriptor(
    "macos/timemachine/destination",
    [
        ("datetime", "ts_last_backup"),
        ("datetime", "ts_last_known_volume_path"),
        ("string", "destination_id"),
        ("string", "name"),
        ("string", "last_known_volume_path"),
        ("string", "result"),
        ("varint", "bytes_used"),
        ("varint", "bytes_available"),
        ("varint", "consistency_scan_required"),
        ("path", "source"),
    ],
)

TimeMachineConfigRecord = TargetRecordDescriptor(
    "macos/timemachine/config",
    [
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class MacOSTimeMachinePlugin(Plugin):
    """Parse ``/Library/Preferences/com.apple.TimeMachine.plist``."""

    __namespace__ = "timemachine"

    PLIST = "Library/Preferences/com.apple.TimeMachine.plist"

    def __init__(self, target):
        super().__init__(target)
        self.path = self.target.fs.path("/") / self.PLIST

    def check_compatible(self) -> None:
        if not self.path.exists():
            raise UnsupportedPluginError("No TimeMachine.plist found")

    def _load(self):
        with self.path.open("rb") as fh:
            return plistlib.load(fh)

    @export(record=TimeMachineDestRecord)
    def destinations(self) -> Iterator[TimeMachineDestRecord]:
        """One record per configured backup destination."""
        try:
            data = self._load()
        except Exception as e:
            self.target.log.warning("Error loading TimeMachine.plist: %s", e)
            return
        for dest in data.get("Destinations", []) or []:
            yield TimeMachineDestRecord(
                ts_last_backup=_dt(dest.get("SnapshotDates", [None])[-1])
                if dest.get("SnapshotDates") else _dt(dest.get("LastDestinationUseDate")),
                ts_last_known_volume_path=_dt(dest.get("LastKnownVolumeNamesByFSEvent")),
                destination_id=(
                    str(dest.get("DestinationID", "")) if dest.get("DestinationID") else ""
                ),
                name=dest.get("LastKnownEncryptionState") or dest.get("BackupAlias", "") or "",
                last_known_volume_path=dest.get("LastKnownVolumeName") or "",
                result=str(dest.get("Result", "")),
                bytes_used=int(dest.get("BytesUsed", 0) or 0),
                bytes_available=int(dest.get("BytesAvailable", 0) or 0),
                consistency_scan_required=int(bool(dest.get("ConsistencyScanRequired", False))),
                source=self.path,
                _target=self.target,
            )

    @export(record=TimeMachineConfigRecord)
    def config(self) -> Iterator[TimeMachineConfigRecord]:
        """Top-level TimeMachine config keys (auto-backup, interval, etc.)."""
        try:
            data = self._load()
        except Exception as e:
            self.target.log.warning("Error loading TimeMachine.plist: %s", e)
            return
        for k, v in data.items():
            if k == "Destinations":
                continue
            yield TimeMachineConfigRecord(
                key=str(k),
                value=str(v)[:500],
                source=self.path,
                _target=self.target,
            )

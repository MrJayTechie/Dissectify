"""macOS Bluetooth Low-Energy devices-seen plugin.

The ``/Library/Bluetooth/com.apple.MobileBluetooth.ledevices.other.db``
SQLite cache records every BLE peripheral the Mac has *observed* (not
necessarily paired): every Apple device, AirTag, fitness band, beacon,
wireless accessory, plus the user's own iCloud-linked devices. The
``OtherDevices`` table has UUID + advertised name + MAC addresses
(``Address`` is the advertised random address, ``ResolvedAddress`` the
underlying identity address) + last-seen / last-connection timestamps.

Critical for proximity-tracking forensics: which Bluetooth devices were
near this Mac and when.
"""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


def _ts(v):
    if not v:
        return None
    try:
        # MobileBluetooth uses Cocoa-epoch seconds in this column.
        return datetime(2001, 1, 1, tzinfo=timezone.utc).fromtimestamp(
            float(v) + 978307200, tz=timezone.utc,
        )
    except (OSError, OverflowError, ValueError, TypeError):
        return None


BLEDeviceRecord = TargetRecordDescriptor(
    "macos/ble/device_seen",
    [
        ("datetime", "ts_last_seen"),
        ("datetime", "ts_last_connection"),
        ("string", "uuid"),
        ("string", "name"),
        ("string", "advertised_address"),
        ("string", "resolved_address"),
        ("string", "icloud_identifier"),
        ("string", "tags"),
        ("varint", "name_origin"),
        ("path", "source"),
    ],
)


class MacOSBLEPlugin(Plugin):
    """Parse ``/Library/Bluetooth/com.apple.MobileBluetooth.ledevices.other.db``."""

    __namespace__ = "ble"

    DB_PATH = "Library/Bluetooth/com.apple.MobileBluetooth.ledevices.other.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = [
            p for p in (self.target.fs.path("/") / self.DB_PATH,) if p.exists()
        ]

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No BLE device database found")

    def _open(self, db_path):
        with db_path.open("rb") as fh:
            data = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(data)
        tmp.flush()
        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=BLEDeviceRecord)
    def devices_seen(self) -> Iterator[BLEDeviceRecord]:
        """One record per BLE peripheral the Mac has observed (paired or not)."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT Uuid, Name, NameOrigin, Address, ResolvedAddress, "
                    "LastSeenTime, LastConnectionTime, Tags, iCloudIdentifier "
                    "FROM OtherDevices ORDER BY LastSeenTime DESC"
                )
                for row in cur:
                    yield BLEDeviceRecord(
                        ts_last_seen=_ts(row["LastSeenTime"]),
                        ts_last_connection=_ts(row["LastConnectionTime"]),
                        uuid=row["Uuid"] or "",
                        name=row["Name"] or "",
                        advertised_address=row["Address"] or "",
                        resolved_address=row["ResolvedAddress"] or "",
                        icloud_identifier=row["iCloudIdentifier"] or "",
                        tags=row["Tags"] or "",
                        name_origin=row["NameOrigin"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except sqlite3.OperationalError as e:
                self.target.log.warning("Error parsing BLE DB %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

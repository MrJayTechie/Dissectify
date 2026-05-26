"""Apple HomeKit plugin.

Reads ``~/Library/HomeKit/core.sqlite`` (+ ``-local`` / ``-cloudkit`` /
``-cloudkit-shared`` siblings) — the on-device HomeKit graph: homes,
rooms, accessories, services, characteristic values, and (most useful
forensically) action sets and triggers (the automations that link them).
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


HomeKitAccessoryRecord = TargetRecordDescriptor(
    "macos/homekit/accessory",
    [
        ("datetime", "ts_added"),
        ("datetime", "ts_modified"),
        ("string", "name"),
        ("string", "manufacturer"),
        ("string", "model"),
        ("string", "serial_number"),
        ("string", "firmware_version"),
        ("string", "category"),
        ("string", "uuid"),
        ("string", "home"),
        ("string", "room"),
        ("path", "source"),
    ],
)

HomeKitHomeRecord = TargetRecordDescriptor(
    "macos/homekit/home",
    [
        ("string", "name"),
        ("string", "uuid"),
        ("varint", "is_current"),
        ("varint", "is_owner"),
        ("path", "source"),
    ],
)

HomeKitTriggerRecord = TargetRecordDescriptor(
    "macos/homekit/trigger",
    [
        ("datetime", "ts_last_fired"),
        ("string", "name"),
        ("string", "uuid"),
        ("string", "trigger_class"),
        ("varint", "enabled"),
        ("path", "source"),
    ],
)


class AppleHomeKitPlugin(Plugin):
    """Parse ``~/Library/HomeKit/*.sqlite``."""

    __namespace__ = "homekit"

    GLOB = "Users/*/Library/HomeKit/*.sqlite"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No HomeKit database found")

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

    def _tables(self, cur):
        return {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}

    @export(record=HomeKitAccessoryRecord)
    def accessories(self) -> Iterator[HomeKitAccessoryRecord]:
        """One record per paired HomeKit accessory (lights, locks, sensors)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_accessories(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing HomeKit accessories %s: %s", db_path, e)

    def _parse_accessories(self, db_path):
        conn, tmp = self._open(db_path)
        try:
            cur = conn.cursor()
            if "ZMKFACCESSORY" not in self._tables(cur):
                return
            cols = {r[1] for r in cur.execute("PRAGMA table_info(ZMKFACCESSORY)").fetchall()}

            def col(*names, default="NULL"):
                for n in names:
                    if n in cols:
                        return n
                return default

            select = ", ".join([
                f"{col('ZCONFIGUREDNAME', 'ZPROVIDEDNAME', 'ZNAME')} AS name",
                f"{col('ZMANUFACTURER', 'ZINITIALMANUFACTURER')} AS manufacturer",
                f"{col('ZMODEL', 'ZINITIALMODEL')} AS model",
                f"{col('ZSERIALNUMBER')} AS serial",
                f"{col('ZFIRMWAREVERSION', 'ZDISPLAYABLEFIRMWAREVERSION')} AS fw",
                f"{col('ZACCESSORYCATEGORY')} AS category",
                f"{col('ZIDENTIFIER', 'ZUNIQUEIDENTIFIER')} AS uuid",
                f"{col('ZLASTSEENDATE', 'ZWRITERTIMESTAMP')} AS ts_added",
                f"{col('ZWRITERTIMESTAMP', 'ZLASTSEENDATE')} AS ts_modified",
            ])
            cur.execute(f"SELECT {select} FROM ZMKFACCESSORY")  # noqa: S608
            for row in cur:
                yield HomeKitAccessoryRecord(
                    ts_added=_cocoa_ts(row["ts_added"]),
                    ts_modified=_cocoa_ts(row["ts_modified"]),
                    name=row["name"] or "",
                    manufacturer=row["manufacturer"] or "",
                    model=row["model"] or "",
                    serial_number=row["serial"] or "",
                    firmware_version=row["fw"] or "",
                    category=str(row["category"] or ""),
                    uuid=row["uuid"] or "",
                    home="",
                    room="",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=HomeKitHomeRecord)
    def homes(self) -> Iterator[HomeKitHomeRecord]:
        """One record per HomeKit home (residence the user configured)."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                if "ZMKFCKHOME" not in self._tables(cur):
                    return
                cols = {r[1] for r in cur.execute("PRAGMA table_info(ZMKFCKHOME)").fetchall()}
                name_col = "ZNAME" if "ZNAME" in cols else "ZHOMENAME"
                uuid_col = "ZUUID" if "ZUUID" in cols else "ZHOMEUUID"
                cur_col = "ZCURRENT" if "ZCURRENT" in cols else "ZCURRENTHOME"
                owner_col = "ZOWNERUSER" if "ZOWNERUSER" in cols else (
                    "ZISOWNER" if "ZISOWNER" in cols else "0"
                )
                cur.execute(
                    f"SELECT {name_col} AS ZNAME, {uuid_col} AS ZUUID, "  # noqa: S608
                    f"{cur_col} AS ZCURRENT, {owner_col} AS ZOWNERUSER FROM ZMKFCKHOME"
                )
                for row in cur:
                    yield HomeKitHomeRecord(
                        name=row["ZNAME"] or "",
                        uuid=row["ZUUID"] or "",
                        is_current=row["ZCURRENT"] or 0,
                        is_owner=row["ZOWNERUSER"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except sqlite3.OperationalError:
                pass
            finally:
                conn.close()
                tmp.close()

    @export(record=HomeKitTriggerRecord)
    def triggers(self) -> Iterator[HomeKitTriggerRecord]:
        """One record per automation trigger (time-of-day, location, event)."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                tables = self._tables(cur)
                # HomeKit stores triggers in ZTRIGGER and variants
                table = "ZTRIGGER" if "ZTRIGGER" in tables else None
                if not table:
                    return
                cols = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}

                def col(*names, default="NULL"):
                    for n in names:
                        if n in cols:
                            return n
                    return default

                select = ", ".join([
                    f"{col('ZNAME')} AS name",
                    f"{col('ZUUID')} AS uuid",
                    f"{col('Z_ENT')} AS klass",
                    f"{col('ZENABLED')} AS enabled",
                    f"{col('ZLASTFIREDATE', 'ZLASTACCESSDATE')} AS ts_last",
                ])
                cur.execute(f"SELECT {select} FROM {table}")  # noqa: S608
                for row in cur:
                    yield HomeKitTriggerRecord(
                        ts_last_fired=_cocoa_ts(row["ts_last"]),
                        name=row["name"] or "",
                        uuid=row["uuid"] or "",
                        trigger_class=str(row["klass"] or ""),
                        enabled=row["enabled"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except sqlite3.OperationalError:
                pass
            finally:
                conn.close()
                tmp.close()

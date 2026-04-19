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
UNIX_EPOCH_2001 = 978307200  # 2001-01-01 as Unix seconds


def _cocoa_ts(value):
    """Convert a PowerLog timestamp to datetime.

    PowerLog column semantics differ by macOS version: older schemas store
    Cocoa seconds (since 2001-01-01), modern ones store Unix seconds. Values
    above the 2001 Unix threshold are already Unix-epoch and must not have the
    Cocoa offset reapplied. Returns None for null/zero.
    """
    if not value or value <= 0:
        return None
    try:
        if value > UNIX_EPOCH_2001:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return COCOA_EPOCH + timedelta(seconds=value)
    except (OSError, OverflowError, ValueError):
        return None


# PLSleepWakeAgent_EventForward_PowerState.State is a numeric code describing
# the CPU/SoC sleep state transition. The mapping is stable across recent
# macOS releases (see IOPMrootDomain source).
_POWER_STATE_MAP = {
    0: "FullWake",
    1: "DarkWake",
    2: "DisplaySleep",
    3: "DeepSleep",
    4: "DeepSleep (Standby)",
    5: "Sleeping",
    6: "Hibernate",
    7: "PowerOff",
}

# PLSleepWakeAgent.Event values (observed).
_POWER_EVENT_MAP = {
    1: "WillSleep",
    2: "DidSleep",
    3: "WillWake",
    4: "DidWake",
    5: "Maintenance",
    6: "Notification",
}

# FrontmostApp ApplicationType values observed in PLApplicationAgent.
_APP_TYPE_MAP = {
    0: "Unknown",
    1: "Daemon",
    2: "Extension",
    3: "Foreground",
    4: "Background",
}


SleepWakeRecord = TargetRecordDescriptor(
    "macos/powerlogs/sleep_wake",
    [
        ("datetime", "ts"),
        ("string", "event"),
        ("string", "state"),
        ("varint", "event_id"),
        ("varint", "state_id"),
        ("string", "reason"),
        ("string", "wake_type"),
        ("string", "driver_wake_reason"),
        ("string", "uuid"),
        ("path", "source"),
    ],
)

AppUsageRecord = TargetRecordDescriptor(
    "macos/powerlogs/app_usage",
    [
        ("datetime", "ts"),
        ("string", "bundle_id"),
        ("string", "app_type"),
        ("varint", "asn"),
        ("path", "source"),
    ],
)

NetworkRecord = TargetRecordDescriptor(
    "macos/powerlogs/network",
    [
        ("datetime", "ts"),
        ("string", "interface"),
        ("varint", "bytes_in"),
        ("varint", "bytes_out"),
        ("path", "source"),
    ],
)


class PowerLogsPlugin(Plugin):
    """Plugin to parse macOS powerlog database.

    Parses sleep/wake events, frontmost-application history, and network
    activity from the CurrentPowerlog.PLSQL database. This database has 250+
    tables and column names vary by macOS version, so each query guards
    against missing columns.

    Location: /private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL
    """

    __namespace__ = "powerlogs"

    DB_GLOB = "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No CurrentPowerlog.PLSQL found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    def _get_columns(self, conn, table_name):
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [col["name"] for col in cursor.fetchall()]

    def _table_exists(self, conn, table_name):
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return cursor.fetchone() is not None

    @staticmethod
    def _safe_get(row, column, columns, default=None):
        if column not in columns:
            return default
        try:
            v = row[column]
        except (IndexError, KeyError):
            return default
        return default if v is None else v

    # ── Sleep / Wake ─────────────────────────────────────────────────────

    @export(record=SleepWakeRecord)
    def sleep_wake(self) -> Iterator[SleepWakeRecord]:
        """Parse sleep/wake power state events from the powerlog database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_sleep_wake(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs sleep_wake at %s: %s", db_path, e)

    def _parse_sleep_wake(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            table = "PLSleepWakeAgent_EventForward_PowerState"
            if not self._table_exists(conn, table):
                return
            columns = self._get_columns(conn, table)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table}")
            for row in cursor:
                ts_val = self._safe_get(row, "timestamp", columns)
                event_id = self._safe_get(row, "Event", columns, default=0) or 0
                state_id = self._safe_get(row, "State", columns, default=0) or 0
                yield SleepWakeRecord(
                    ts=_cocoa_ts(ts_val),
                    event=_POWER_EVENT_MAP.get(event_id, f"event_{event_id}"),
                    state=_POWER_STATE_MAP.get(state_id, f"state_{state_id}"),
                    event_id=event_id,
                    state_id=state_id,
                    reason=str(self._safe_get(row, "Reason", columns, default="") or ""),
                    wake_type=str(self._safe_get(row, "WakeType", columns, default="") or ""),
                    driver_wake_reason=str(
                        self._safe_get(row, "DriverWakeReason", columns, default="") or ""
                    ),
                    uuid=str(self._safe_get(row, "UUID", columns, default="") or ""),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── App usage (frontmost application history) ────────────────────────

    @export(record=AppUsageRecord)
    def app_usage(self) -> Iterator[AppUsageRecord]:
        """Parse frontmost-application history from the powerlog database.

        Uses PLApplicationAgent_EventForward_FrontmostApp — the
        PLApplicationAgent_EventForward_Application table exists but is
        typically near-empty on modern macOS and was the source of the
        previous ~2-row output.
        """
        for db_path in self._db_paths:
            try:
                yield from self._parse_app_usage(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs app_usage at %s: %s", db_path, e)

    def _parse_app_usage(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            # Prefer FrontmostApp (populated on macOS 13+). Fall back to
            # AppLifecycle which also tracks activation events.
            for table in (
                "PLApplicationAgent_EventForward_FrontmostApp",
                "PLApplicationAgent_EventForward_AppLifecycle",
            ):
                if not self._table_exists(conn, table):
                    continue
                columns = self._get_columns(conn, table)
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {table}")
                count = 0
                for row in cursor:
                    ts_val = self._safe_get(row, "timestamp", columns)
                    bundle = str(self._safe_get(row, "BundleID", columns, default="") or "")
                    app_type_id = self._safe_get(row, "ApplicationType", columns, default=0) or 0
                    asn = self._safe_get(row, "ASN", columns, default=0) or 0
                    yield AppUsageRecord(
                        ts=_cocoa_ts(ts_val),
                        bundle_id=bundle,
                        app_type=_APP_TYPE_MAP.get(app_type_id, f"type_{app_type_id}"),
                        asn=asn,
                        source=db_path,
                        _target=self.target,
                    )
                    count += 1
                if count:
                    return  # first populated table wins
        finally:
            conn.close()
            tmp.close()

    # ── Network (cumulative per interface) ──────────────────────────────

    @export(record=NetworkRecord)
    def network(self) -> Iterator[NetworkRecord]:
        """Parse cumulative network usage per interface from the powerlog database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_network(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs network at %s: %s", db_path, e)

    def _parse_network(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            table = "PLNetworkAgent_EventBackward_CumulativeNetworkUsage"
            if not self._table_exists(conn, table):
                return
            columns = self._get_columns(conn, table)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table}")
            for row in cursor:
                ts_val = self._safe_get(row, "timestamp", columns)
                yield NetworkRecord(
                    ts=_cocoa_ts(ts_val),
                    interface=str(self._safe_get(row, "Interface", columns, default="") or ""),
                    bytes_in=self._safe_get(row, "DownBytes", columns, default=0) or 0,
                    bytes_out=self._safe_get(row, "UpBytes", columns, default=0) or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

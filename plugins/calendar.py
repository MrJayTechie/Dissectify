"""Apple Calendar plugin.

Reads ``~/Library/Group Containers/group.com.apple.calendar/Calendar.sqlitedb``
which holds every calendar event, alarm, attendee, attachment, and recurrence
the user has either created locally or synced from iCloud / Exchange.

The relevant tables are:

- ``CalendarItem`` (one row per event / task / reminder reference)
- ``Calendar``     (one row per calendar — title, color, account)
- ``Alarm``        (linked alerts with trigger offsets)
- ``Identity``     (organizer / attendee identities)
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


CalendarEventRecord = TargetRecordDescriptor(
    "macos/calendar/event",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_due"),
        ("datetime", "ts_completed"),
        ("datetime", "ts_created"),
        ("datetime", "ts_last_modified"),
        ("string", "summary"),
        ("string", "description"),
        ("string", "location"),
        ("string", "url"),
        ("string", "conference_url"),
        ("string", "uuid"),
        ("string", "calendar"),
        ("string", "start_tz"),
        ("string", "end_tz"),
        ("varint", "all_day"),
        ("varint", "status"),
        ("varint", "has_attendees"),
        ("varint", "has_attachment"),
        ("varint", "entity_type"),
        ("path", "source"),
    ],
)

CalendarCalendarRecord = TargetRecordDescriptor(
    "macos/calendar/calendar",
    [
        ("string", "title"),
        ("string", "owner_identity"),
        ("string", "calendar_type"),
        ("varint", "color"),
        ("string", "external_id"),
        ("path", "source"),
    ],
)

CalendarAlarmRecord = TargetRecordDescriptor(
    "macos/calendar/alarm",
    [
        ("datetime", "ts_trigger"),
        ("string", "owner_summary"),
        ("string", "action"),
        ("varint", "trigger_interval"),
        ("path", "source"),
    ],
)


class AppleCalendarPlugin(Plugin):
    """Parse ``~/Library/Group Containers/group.com.apple.calendar/Calendar.sqlitedb``."""

    __namespace__ = "calendar"

    DB_GLOB = "Users/*/Library/Group Containers/group.com.apple.calendar/Calendar.sqlitedb"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Calendar database found")

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

    @export(record=CalendarEventRecord)
    def events(self) -> Iterator[CalendarEventRecord]:
        """Yield one record per CalendarItem (events, tasks, birthdays)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_events(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Calendar events %s: %s", db_path, e)

    def _parse_events(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT ci.summary, ci.description, ci.start_date, ci.start_tz,
                       ci.end_date, ci.end_tz, ci.due_date, ci.completion_date,
                       ci.creation_date, ci.last_modified, ci.all_day, ci.status,
                       ci.url, ci.conference_url, ci.UUID, ci.has_recurrences,
                       ci.has_attachment, ci.has_attendees, ci.entity_type,
                       c.title  AS calendar_title,
                       loc.title AS location_title
                FROM CalendarItem ci
                LEFT JOIN Calendar c   ON c.ROWID  = ci.calendar_id
                LEFT JOIN Location loc ON loc.ROWID = ci.location_id
                ORDER BY ci.start_date DESC
                """,
            )
            for row in cur:
                yield CalendarEventRecord(
                    ts_start=_cocoa_ts(row["start_date"]),
                    ts_end=_cocoa_ts(row["end_date"]),
                    ts_due=_cocoa_ts(row["due_date"]),
                    ts_completed=_cocoa_ts(row["completion_date"]),
                    ts_created=_cocoa_ts(row["creation_date"]),
                    ts_last_modified=_cocoa_ts(row["last_modified"]),
                    summary=row["summary"] or "",
                    description=row["description"] or "",
                    location=row["location_title"] or "",
                    url=row["url"] or "",
                    conference_url=row["conference_url"] or "",
                    uuid=row["UUID"] or "",
                    calendar=row["calendar_title"] or "",
                    start_tz=row["start_tz"] or "",
                    end_tz=row["end_tz"] or "",
                    all_day=row["all_day"] or 0,
                    status=row["status"] or 0,
                    has_attendees=row["has_attendees"] or 0,
                    has_attachment=row["has_attachment"] or 0,
                    entity_type=row["entity_type"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=CalendarCalendarRecord)
    def calendars(self) -> Iterator[CalendarCalendarRecord]:
        """One record per configured calendar (account / source identifier)."""
        for db_path in self._db_paths:
            conn, tmp = self._open_db(db_path)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        SELECT c.title, c.color, c.type, c.external_id,
                               i.email AS owner_email
                        FROM Calendar c
                        LEFT JOIN Identity i ON i.ROWID = c.self_identity
                        """,
                    )
                except sqlite3.OperationalError:
                    cur.execute("SELECT title, color, type, external_id FROM Calendar")
                for row in cur:
                    yield CalendarCalendarRecord(
                        title=row["title"] or "",
                        owner_identity=row["owner_email"] if "owner_email" in row.keys() else "",
                        calendar_type=str(row["type"] or ""),
                        color=row["color"] or 0,
                        external_id=row["external_id"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

    @export(record=CalendarAlarmRecord)
    def alarms(self) -> Iterator[CalendarAlarmRecord]:
        """One record per scheduled alarm with the linked event summary."""
        for db_path in self._db_paths:
            conn, tmp = self._open_db(db_path)
            try:
                cur = conn.cursor()
                # Alarm.action exists on iOS Calendar but not macOS — type is
                # used instead. Owner FK is calendaritem_owner_id (or owner_id
                # on older builds).
                cols = {r[1] for r in cur.execute("PRAGMA table_info(Alarm)").fetchall()}
                action_col = "a.action" if "action" in cols else (
                    "CAST(a.type AS TEXT)" if "type" in cols else "''"
                )
                owner_fk = "calendaritem_owner_id" if "calendaritem_owner_id" in cols else (
                    "owner_id" if "owner_id" in cols else None
                )
                if owner_fk:
                    cur.execute(
                        f"""
                        SELECT a.trigger_date, a.trigger_interval,
                               {action_col} AS action,
                               ci.summary  AS owner_summary
                        FROM Alarm a
                        LEFT JOIN CalendarItem ci ON ci.ROWID = a.{owner_fk}
                        """,  # noqa: S608
                    )
                else:
                    cur.execute(
                        f"SELECT trigger_date, trigger_interval, {action_col} AS action, "  # noqa: S608
                        "'' AS owner_summary FROM Alarm"
                    )
                for row in cur:
                    yield CalendarAlarmRecord(
                        ts_trigger=_cocoa_ts(row["trigger_date"]),
                        owner_summary=(
                            row["owner_summary"]
                            if "owner_summary" in row.keys() else ""
                        ) or "",
                        action=str(row["action"] or ""),
                        trigger_interval=row["trigger_interval"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

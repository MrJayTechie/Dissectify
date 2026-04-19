from __future__ import annotations

import sqlite3
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# iMessage timestamps: nanoseconds since 2001-01-01 (Cocoa epoch)
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ns_ts(value):
    """Convert a chat.db timestamp to datetime. Returns None for null/zero.

    Two on-disk formats are in play on modern macOS:
      * ``message.date`` — nanoseconds since 2001-01-01 (~1e18 magnitude).
      * ``attachment.created_date`` — plain seconds since 2001-01-01
        (~1e9 magnitude).
    Detect the units from magnitude; anything below ~1e12 is seconds.
    """
    if not value:
        return None
    try:
        seconds = value if value < 1_000_000_000_000 else value / 1_000_000_000
        return COCOA_EPOCH + timedelta(seconds=seconds)
    except (OSError, OverflowError, ValueError):
        return None


# The `message.text` column has been NULL on every macOS build since 10.14;
# the message body is serialised into `attributedBody` using Apple's
# typedstream format (the old NSArchiver output, not NSKeyedArchiver).
#
# We extract the plain text by locating the NSString payload header
# (class ref `\x84\x01+` where `+` is the typedstream type code for an
# NSString) followed by a length-prefixed UTF-8 run. That covers virtually
# every message body macOS writes today; exotic NSAttributedString runs
# (images, stickers, tapbacks) are typedstream objects without a leading
# NSString and are returned as None so the caller can fall back.
_ATTRIBUTEDBODY_HEADER = b"streamtyped"
_ATTRIBUTEDBODY_STRING_MARKER = b"\x84\x01+"


def _typedstream_length(blob, offset):
    """Read a typedstream-encoded length field, return (length, new_offset)
    or (None, offset) if we run off the end."""
    if offset >= len(blob):
        return None, offset
    first = blob[offset]
    offset += 1
    # One-byte form. 0x81/0x82 are extension markers used by typedstream
    # for values that don't fit.
    if first < 0x81:
        return first, offset
    if first == 0x81:
        if offset + 2 > len(blob):
            return None, offset
        val = struct.unpack(">H", blob[offset:offset + 2])[0]
        return val, offset + 2
    if first == 0x82:
        if offset + 4 > len(blob):
            return None, offset
        val = struct.unpack(">I", blob[offset:offset + 4])[0]
        return val, offset + 4
    # Signed negative shortcut — not expected for message bodies.
    return None, offset


def _decode_attributed_body(blob):
    """Extract the plain-text body from a chat.db `attributedBody` blob.
    Returns None when the blob is empty, not a typedstream, or carries a
    non-text payload (attachment placeholder, rich content, etc.)."""
    if not blob or not isinstance(blob, (bytes, bytearray)):
        return None
    if _ATTRIBUTEDBODY_HEADER not in blob[:32]:
        return None

    # Find the NSString class reference immediately preceding the text.
    # Messages always use this single sequence for the body string.
    idx = blob.find(_ATTRIBUTEDBODY_STRING_MARKER)
    if idx < 0:
        return None
    offset = idx + len(_ATTRIBUTEDBODY_STRING_MARKER)

    length, offset = _typedstream_length(blob, offset)
    if length is None or length <= 0:
        return None
    if offset + length > len(blob):
        length = len(blob) - offset

    try:
        return blob[offset:offset + length].decode("utf-8")
    except UnicodeDecodeError:
        return blob[offset:offset + length].decode("utf-8", errors="replace")


MessageRecord = TargetRecordDescriptor(
    "macos/imessage/messages",
    [
        ("datetime", "ts"),
        ("string", "text"),
        ("boolean", "is_from_me"),
        ("boolean", "is_read"),
        ("string", "service"),
        ("string", "handle_id"),
        ("string", "associated_message_guid"),
        ("string", "balloon_bundle_id"),
        ("boolean", "cache_has_attachments"),
        ("path", "source"),
    ],
)

ChatRecord = TargetRecordDescriptor(
    "macos/imessage/chats",
    [
        ("string", "chat_identifier"),
        ("string", "service_name"),
        ("string", "display_name"),
        ("string", "room_name"),
        ("boolean", "is_archived"),
        ("path", "source"),
    ],
)

AttachmentRecord = TargetRecordDescriptor(
    "macos/imessage/attachments",
    [
        ("datetime", "ts_created"),
        ("string", "filename"),
        ("string", "mime_type"),
        ("string", "uti"),
        ("varint", "transfer_state"),
        ("boolean", "is_outgoing"),
        ("varint", "total_bytes"),
        ("path", "source"),
    ],
)


class IMessagePlugin(Plugin):
    """Plugin to parse macOS iMessage chat.db.

    Parses messages, chats, and attachments from the iMessage database.

    Location: ~/Library/Messages/chat.db
    """

    __namespace__ = "imessage"

    DB_GLOB = "Users/*/Library/Messages/chat.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No iMessage chat.db found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    # ── Messages ────────────────────────────────────────────────────────

    @export(record=MessageRecord)
    def messages(self) -> Iterator[MessageRecord]:
        """Parse iMessage/SMS messages with sender handle information."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_messages(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessages at %s: %s", db_path, e)

    def _parse_messages(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    m.date,
                    m.text,
                    m.attributedBody,
                    m.is_from_me,
                    m.is_read,
                    m.service,
                    h.id AS handle_id,
                    m.associated_message_guid,
                    m.balloon_bundle_id,
                    m.cache_has_attachments
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                ORDER BY m.date DESC
            """)
            for row in cursor:
                text = row["text"]
                if not text:
                    # Modern macOS stores the body in attributedBody, not text.
                    text = _decode_attributed_body(row["attributedBody"]) or ""
                yield MessageRecord(
                    ts=_cocoa_ns_ts(row["date"]),
                    text=text,
                    is_from_me=bool(row["is_from_me"]),
                    is_read=bool(row["is_read"]),
                    service=row["service"] or "",
                    handle_id=row["handle_id"] or "",
                    associated_message_guid=row["associated_message_guid"] or "",
                    balloon_bundle_id=row["balloon_bundle_id"] or "",
                    cache_has_attachments=bool(row["cache_has_attachments"]),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Chats ───────────────────────────────────────────────────────────

    @export(record=ChatRecord)
    def chats(self) -> Iterator[ChatRecord]:
        """Parse iMessage/SMS chat entries."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_chats(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessage chats at %s: %s", db_path, e)

    def _parse_chats(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT chat_identifier, service_name, display_name,
                       room_name, is_archived
                FROM chat
            """)
            for row in cursor:
                yield ChatRecord(
                    chat_identifier=row["chat_identifier"] or "",
                    service_name=row["service_name"] or "",
                    display_name=row["display_name"] or "",
                    room_name=row["room_name"] or "",
                    is_archived=bool(row["is_archived"]),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Attachments ─────────────────────────────────────────────────────

    @export(record=AttachmentRecord)
    def attachments(self) -> Iterator[AttachmentRecord]:
        """Parse iMessage/SMS attachments."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_attachments(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessage attachments at %s: %s", db_path, e)

    def _parse_attachments(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            # attachment.created_date is usually 0 on modern macOS. Join
            # message_attachment_join + message so we can fall back to the
            # linked message's date.
            cursor.execute("""
                SELECT a.created_date AS att_created,
                       a.filename, a.mime_type, a.uti,
                       a.transfer_state, a.is_outgoing, a.total_bytes,
                       m.date AS msg_date
                FROM attachment a
                LEFT JOIN message_attachment_join maj ON maj.attachment_id = a.ROWID
                LEFT JOIN message m ON m.ROWID = maj.message_id
                ORDER BY COALESCE(NULLIF(a.created_date, 0), m.date) DESC
            """)
            for row in cursor:
                ts = _cocoa_ns_ts(row["att_created"]) or _cocoa_ns_ts(row["msg_date"])
                yield AttachmentRecord(
                    ts_created=ts,
                    filename=row["filename"] or "",
                    mime_type=row["mime_type"] or "",
                    uti=row["uti"] or "",
                    transfer_state=row["transfer_state"] or 0,
                    is_outgoing=bool(row["is_outgoing"]),
                    total_bytes=row["total_bytes"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

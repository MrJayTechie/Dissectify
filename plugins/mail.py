"""Apple Mail.app plugin.

Reads the ``Envelope Index`` SQLite catalog under
``~/Library/Mail/V<n>/MailData/`` (V10 on Sequoia / Tahoe) for message
metadata. Bodies live in per-message ``.emlx`` files under the same V<n>
tree and are not parsed here — Envelope Index alone gives the analyst
sender, recipient, subject, date, mailbox, attachment count, and flag
state.
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


def _unix_ts(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OSError, OverflowError, ValueError, TypeError):
        return None


MailMessageRecord = TargetRecordDescriptor(
    "macos/mail/message",
    [
        ("datetime", "ts_received"),
        ("datetime", "ts_sent"),
        ("string", "sender"),
        ("string", "subject"),
        ("string", "mailbox"),
        ("string", "snippet"),
        ("varint", "size_bytes"),
        ("varint", "flags"),
        ("varint", "read"),
        ("varint", "deleted"),
        ("varint", "flagged"),
        ("varint", "attachment_count"),
        ("string", "message_id"),
        ("path", "source"),
    ],
)

MailAttachmentRecord = TargetRecordDescriptor(
    "macos/mail/attachment",
    [
        ("varint", "message_rowid"),
        ("string", "name"),
        ("string", "content_type"),
        ("varint", "size_bytes"),
        ("path", "source"),
    ],
)


class AppleMailPlugin(Plugin):
    """Parse ``~/Library/Mail/V*/MailData/Envelope Index`` (and -wal/-shm)."""

    __namespace__ = "mail"

    INDEX_GLOB = "Users/*/Library/Mail/V*/MailData/Envelope Index"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.INDEX_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Mail Envelope Index found")

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

    @export(record=MailMessageRecord)
    def messages(self) -> Iterator[MailMessageRecord]:
        """Yield one record per indexed message with sender / subject /
        mailbox / received timestamp / read & flagged state."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_messages(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Mail Envelope Index %s: %s", db_path, e)

    def _parse_messages(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cur = conn.cursor()
            cols = {r[1] for r in cur.execute("PRAGMA table_info(messages)").fetchall()}

            def col(name, default="NULL"):
                return f"m.{name}" if name in cols else default

            # Pick whichever attachment-fk column the schema uses (Apple
            # uses `message` in modern Envelope Index; older Mail builds
            # used `message_id`).
            att_cols = {r[1] for r in cur.execute("PRAGMA table_info(attachments)").fetchall()}
            att_fk = "message" if "message" in att_cols else (
                "message_id" if "message_id" in att_cols else None
            )

            query = f"""
                SELECT m.ROWID                            AS rowid,
                       {col('date_received')}             AS date_received,
                       {col('date_sent')}                 AS date_sent,
                       {col('size')}                      AS size,
                       {col('flags')}                     AS flags,
                       {col('read')}                      AS read,
                       {col('deleted')}                   AS deleted,
                       {col('flagged')}                   AS flagged,
                       {(
                           f"(SELECT COUNT(*) FROM attachments a WHERE a.{att_fk} = m.ROWID)"
                           if att_fk else "0"
                       )}                                  AS attachment_count,
                       addr.address                       AS sender_addr,
                       addr.comment                       AS sender_name,
                       s.subject                          AS subject,
                       mb.url                             AS mailbox,
                       {col('message_id', "''")}          AS msg_id
                FROM messages m
                LEFT JOIN addresses addr ON addr.ROWID = m.sender
                LEFT JOIN subjects  s    ON s.ROWID    = m.subject
                LEFT JOIN mailboxes mb   ON mb.ROWID   = m.mailbox
                ORDER BY m.date_received DESC
            """
            cur.execute(query)

            for row in cur:
                sender_addr = row["sender_addr"] or ""
                sender_name = row["sender_name"] or ""
                sender = (
                    f"{sender_name} <{sender_addr}>"
                    if sender_name and sender_addr
                    else sender_addr or sender_name
                )
                yield MailMessageRecord(
                    ts_received=_unix_ts(row["date_received"]),
                    ts_sent=_unix_ts(row["date_sent"]),
                    sender=sender,
                    subject=row["subject"] or "",
                    mailbox=row["mailbox"] or "",
                    snippet="",
                    size_bytes=row["size"] or 0,
                    flags=row["flags"] or 0,
                    read=row["read"] or 0,
                    deleted=row["deleted"] or 0,
                    flagged=row["flagged"] or 0,
                    attachment_count=row["attachment_count"] or 0,
                    message_id=str(row["msg_id"] or ""),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=MailAttachmentRecord)
    def attachments(self) -> Iterator[MailAttachmentRecord]:
        """Yield one record per indexed attachment (name + MIME + size)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_attachments(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Mail attachments %s: %s", db_path, e)

    def _parse_attachments(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cur = conn.cursor()
            cols = {r[1] for r in cur.execute("PRAGMA table_info(attachments)").fetchall()}
            if not cols:
                return
            fk = "message" if "message" in cols else "message_id"
            name_col = "name" if "name" in cols else (
                "filename" if "filename" in cols else "''"
            )
            mime_col = "mime_type" if "mime_type" in cols else (
                "content_type" if "content_type" in cols else "''"
            )
            size_col = "size_in_bytes" if "size_in_bytes" in cols else (
                "size" if "size" in cols else "0"
            )
            cur.execute(
                f"SELECT {fk} AS fk, {name_col} AS name, "  # noqa: S608
                f"{mime_col} AS mime, {size_col} AS sz FROM attachments"
            )
            for row in cur:
                yield MailAttachmentRecord(
                    message_rowid=row["fk"] or 0,
                    name=row["name"] or "",
                    content_type=row["mime"] or "",
                    size_bytes=row["sz"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

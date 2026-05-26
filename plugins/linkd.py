"""macOS LinkPresentation (linkd) cache plugin.

The ``linkd.metadatastore.sqlite3`` cache (under one of the user's Daemon
Containers) holds **every URL** for which the OS generated a rich
preview — links shared via Messages, Mail, Notes, Safari Share Sheet,
Shortcuts, third-party apps using the LinkPresentation framework, etc.
Schema columns of interest: ``urlString``, ``title``, ``summary``,
``date``, ``bundles`` table linking each preview to the source app.
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


LinkdLinkRecord = TargetRecordDescriptor(
    "macos/linkd/link",
    [
        ("datetime", "ts"),
        ("string", "url"),
        ("string", "title"),
        ("string", "summary"),
        ("string", "bundles"),
        ("path", "source"),
    ],
)


class MacOSLinkdPlugin(Plugin):
    """Parse linkd's metadata store."""

    __namespace__ = "linkd"

    GLOB = "Users/*/Library/Daemon Containers/*/Data/database/linkd.metadatastore.sqlite3"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No linkd metadata store found")

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

    @export(record=LinkdLinkRecord)
    def links(self) -> Iterator[LinkdLinkRecord]:
        """One record per rich-preview-generated URL (with timestamp + source bundles)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing linkd %s: %s", db_path, e)

    def _parse(self, db_path):
        conn, tmp = self._open(db_path)
        try:
            cur = conn.cursor()
            tables = {r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            # Newer schema: metadata table
            link_table = next(
                (t for t in ("metadata", "Metadata", "LPMetadata", "richLinkMetadata") if t in tables),
                None,
            )
            if not link_table:
                return
            cols = {r[1] for r in cur.execute(f"PRAGMA table_info({link_table})").fetchall()}

            def col(*names, default="NULL"):
                for n in names:
                    if n in cols:
                        return n
                return default

            url_col = col("urlString", "url", "URL")
            title_col = col("title", "siteName")
            summary_col = col("summary", "subtitle")
            ts_col = col("date", "createdTimestamp", "modifiedTimestamp")

            cur.execute(
                f"SELECT rowid, {url_col} AS url, {title_col} AS title, "  # noqa: S608
                f"{summary_col} AS summary, {ts_col} AS ts FROM {link_table}"
            )
            bundles_table = next(
                (t for t in ("bundles", "linkBundles", "LPBundle") if t in tables),
                None,
            )
            for row in cur:
                bundles = ""
                if bundles_table:
                    try:
                        bc = conn.cursor()
                        # Try a couple of likely join columns
                        for fk in ("metadata_id", "metadataId", "rowid"):
                            try:
                                bc.execute(
                                    f"SELECT bundleIdentifier FROM {bundles_table} "  # noqa: S608
                                    f"WHERE {fk}=?",
                                    (row["rowid"],),
                                )
                                bundles = ",".join(b[0] for b in bc.fetchall() if b and b[0])
                                if bundles:
                                    break
                            except sqlite3.OperationalError:
                                continue
                    except sqlite3.OperationalError:
                        pass
                yield LinkdLinkRecord(
                    ts=_cocoa_ts(row["ts"]),
                    url=row["url"] or "",
                    title=row["title"] or "",
                    summary=row["summary"] or "",
                    bundles=bundles,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

"""Apple Identity Services (IDS) plugin.

Reads the on-device Apple-ID identity caches under
``~/Library/IdentityServices/``:

- ``ids-query.db`` — every iMessage / FaceTime identity query (which
  handles were looked up + when), per-handle session keys, and the
  device set associated with each handle. Useful to enumerate the user's
  paired iMessage/FaceTime devices.
- ``TetraDB-identityservicesd.db`` — newer Apple-ID device registry
  (Tetra) that stores device identifiers and trust state.
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


IDSHandleRecord = TargetRecordDescriptor(
    "macos/ids/handle",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_last_query"),
        ("string", "handle"),
        ("string", "short_handle"),
        ("string", "service"),
        ("path", "source"),
    ],
)


class AppleIDSPlugin(Plugin):
    """Parse ``~/Library/IdentityServices/ids-query.db`` and TetraDB."""

    __namespace__ = "ids"

    GLOB = "Users/*/Library/IdentityServices/ids-query.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No ids-query.db found")

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

    @export(record=IDSHandleRecord)
    def handles(self) -> Iterator[IDSHandleRecord]:
        """One record per IDS short-handle (per-service Apple-ID identity)."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if "ZIDSQUERYSDSHORTHANDLE" not in tables:
                    continue
                cols = {r[1] for r in cur.execute(
                    "PRAGMA table_info(ZIDSQUERYSDSHORTHANDLE)"
                ).fetchall()}

                def col(*names, default="NULL"):
                    for n in names:
                        if n in cols:
                            return n
                    return default

                cur.execute(
                    f"SELECT {col('ZSHORTHANDLE', 'ZHANDLE')} AS short, "  # noqa: S608
                    f"{col('ZURI', 'ZNORMALIZEDURI')} AS uri, "
                    f"{col('ZSERVICE')} AS service, "
                    f"{col('ZCREATIONDATE')} AS ts_created, "
                    f"{col('ZLASTACCESSDATE', 'ZLASTUPDATED')} AS ts_access "
                    "FROM ZIDSQUERYSDSHORTHANDLE"
                )
                for row in cur:
                    yield IDSHandleRecord(
                        ts_created=_cocoa_ts(row["ts_created"]),
                        ts_last_query=_cocoa_ts(row["ts_access"]),
                        handle=row["uri"] or "",
                        short_handle=row["short"] or "",
                        service=row["service"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except sqlite3.OperationalError as e:
                self.target.log.warning("Error parsing IDS DB %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

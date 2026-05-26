"""Apple Photos plugin.

Reads ``~/Pictures/Photos Library.photoslibrary/database/Photos.sqlite``
(the main library) plus the syndicated and generative-playground libraries
at ``~/Library/Photos/Libraries/*.photoslibrary/database/Photos.sqlite``.

Schema is Core Data Z-prefix; the most useful tables are:

- ``ZASSET``         — one row per photo / video with capture date, location, EXIF, kind
- ``ZALBUM``         — albums (user + Smart + cloud-shared)
- ``ZPERSON``        — recognised persons across the library
- ``ZGENERICASSET``  — present on some macOS versions instead of ZASSET
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


def _coord(value):
    """Photos uses -180.0 as 'no GPS' sentinel. Strip it."""
    if value is None:
        return None
    try:
        v = float(value)
        if -180.0 < v < 180.0:
            return v
    except (ValueError, TypeError):
        pass
    return None


PhotosAssetRecord = TargetRecordDescriptor(
    "macos/photos/asset",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_added"),
        ("datetime", "ts_modified"),
        ("datetime", "ts_trashed"),
        ("string", "filename"),
        ("string", "directory"),
        ("string", "uti"),
        ("string", "uuid"),
        ("float", "latitude"),
        ("float", "longitude"),
        ("varint", "width"),
        ("varint", "height"),
        ("float", "duration"),
        ("varint", "favorite"),
        ("varint", "hidden"),
        ("varint", "trashed"),
        ("varint", "kind"),
        ("path", "source"),
    ],
)

PhotosAlbumRecord = TargetRecordDescriptor(
    "macos/photos/album",
    [
        ("datetime", "ts_created"),
        ("string", "title"),
        ("string", "uuid"),
        ("varint", "kind"),
        ("varint", "asset_count"),
        ("path", "source"),
    ],
)

PhotosPersonRecord = TargetRecordDescriptor(
    "macos/photos/person",
    [
        ("string", "full_name"),
        ("string", "uuid"),
        ("varint", "face_count"),
        ("path", "source"),
    ],
)


class ApplePhotosPlugin(Plugin):
    """Parse ``Photos.sqlite`` databases under the user's Photos libraries."""

    __namespace__ = "photos"

    DB_GLOBS = [
        "Users/*/Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
        "Users/*/Library/Photos/Libraries/*.photoslibrary/database/Photos.sqlite",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        for pat in self.DB_GLOBS:
            self._db_paths.extend(self.target.fs.path("/").glob(pat))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Photos library found")

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

    @export(record=PhotosAssetRecord)
    def assets(self) -> Iterator[PhotosAssetRecord]:
        """One record per photo / video / screenshot with EXIF + GPS."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_assets(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Photos assets %s: %s", db_path, e)

    def _parse_assets(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cur = conn.cursor()
            table = self._asset_table(cur)
            if table is None:
                return
            cols = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}

            def col(*names, default="NULL"):
                for n in names:
                    if n in cols:
                        return n
                return default

            select = ", ".join([
                f"{col('ZDATECREATED')} AS ts_created",
                f"{col('ZADDEDDATE')} AS ts_added",
                f"{col('ZMODIFICATIONDATE')} AS ts_modified",
                f"{col('ZTRASHEDDATE')} AS ts_trashed",
                f"{col('ZFILENAME')} AS filename",
                f"{col('ZDIRECTORY')} AS directory",
                f"{col('ZUNIFORMTYPEIDENTIFIER')} AS uti",
                f"{col('ZUUID')} AS uuid",
                f"{col('ZLATITUDE')} AS latitude",
                f"{col('ZLONGITUDE')} AS longitude",
                f"{col('ZWIDTH', default='0')} AS width",
                f"{col('ZHEIGHT', default='0')} AS height",
                f"{col('ZDURATION', default='0')} AS duration",
                f"{col('ZFAVORITE', default='0')} AS favorite",
                f"{col('ZHIDDEN', default='0')} AS hidden",
                f"{col('ZTRASHEDSTATE', default='0')} AS trashed",
                f"{col('ZKIND', default='0')} AS kind",
            ])
            cur.execute(f"SELECT {select} FROM {table} ORDER BY ZDATECREATED DESC")  # noqa: S608
            for row in cur:
                yield PhotosAssetRecord(
                    ts_created=_cocoa_ts(row["ts_created"]),
                    ts_added=_cocoa_ts(row["ts_added"]),
                    ts_modified=_cocoa_ts(row["ts_modified"]),
                    ts_trashed=_cocoa_ts(row["ts_trashed"]),
                    filename=row["filename"] or "",
                    directory=row["directory"] or "",
                    uti=row["uti"] or "",
                    uuid=row["uuid"] or "",
                    latitude=_coord(row["latitude"]),
                    longitude=_coord(row["longitude"]),
                    width=row["width"] or 0,
                    height=row["height"] or 0,
                    duration=row["duration"] or 0.0,
                    favorite=row["favorite"] or 0,
                    hidden=row["hidden"] or 0,
                    trashed=row["trashed"] or 0,
                    kind=row["kind"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    def _asset_table(self, cur):
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        for cand in ("ZASSET", "ZGENERICASSET"):
            if cand in tables:
                return cand
        return None

    @export(record=PhotosAlbumRecord)
    def albums(self) -> Iterator[PhotosAlbumRecord]:
        """One record per user album / smart album / cloud-shared album."""
        for db_path in self._db_paths:
            conn, tmp = self._open_db(db_path)
            try:
                cur = conn.cursor()
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if "ZGENERICALBUM" in tables:
                    cur.execute(
                        "SELECT ZTITLE, ZUUID, ZKIND, ZCREATIONDATE, ZCACHEDCOUNT "
                        "FROM ZGENERICALBUM ORDER BY ZCREATIONDATE DESC"
                    )
                elif "ZALBUM" in tables:
                    cur.execute(
                        "SELECT ZTITLE, ZUUID, ZKIND, ZCREATIONDATE, 0 AS ZCACHEDCOUNT "
                        "FROM ZALBUM ORDER BY ZCREATIONDATE DESC"
                    )
                else:
                    return
                for row in cur:
                    yield PhotosAlbumRecord(
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        title=row["ZTITLE"] or "",
                        uuid=row["ZUUID"] or "",
                        kind=row["ZKIND"] or 0,
                        asset_count=row["ZCACHEDCOUNT"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

    @export(record=PhotosPersonRecord)
    def persons(self) -> Iterator[PhotosPersonRecord]:
        """One record per recognised person across the library."""
        for db_path in self._db_paths:
            conn, tmp = self._open_db(db_path)
            try:
                cur = conn.cursor()
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if "ZPERSON" not in tables:
                    return
                cols = {r[1] for r in cur.execute("PRAGMA table_info(ZPERSON)").fetchall()}
                name_col = "ZFULLNAME" if "ZFULLNAME" in cols else "ZDISPLAYNAME"
                count_col = "ZFACECOUNT" if "ZFACECOUNT" in cols else (
                    "ZCACHEDFACECOUNT" if "ZCACHEDFACECOUNT" in cols else "0"
                )
                # Photos creates one ZPERSON row per face cluster — most are
                # unnamed (the user hasn't tagged them). Order so named
                # clusters appear first; emit all rows so the analyst can
                # count unnamed clusters too but the leading rows carry the
                # most signal.
                cur.execute(
                    f"SELECT {name_col} AS full_name, ZPERSONUUID AS uuid, "  # noqa: S608
                    f"{count_col} AS face_count FROM ZPERSON "
                    f"ORDER BY CASE WHEN {name_col} IS NULL OR {name_col} = '' "
                    "THEN 1 ELSE 0 END, face_count DESC"
                )
                for row in cur:
                    yield PhotosPersonRecord(
                        full_name=row["full_name"] or "",
                        uuid=row["uuid"] or "",
                        face_count=row["face_count"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

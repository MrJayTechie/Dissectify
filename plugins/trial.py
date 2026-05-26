"""Apple Trial (experimentation) framework plugin.

``~/Library/Trial/v7/Database/triald.db`` records the A/B experiments
Apple's Trial framework currently has this device enrolled in:
per-experiment treatment paths, rollout history, dynamic namespaces.
Useful both for "which Apple features were toggled on this device" and
for matching user-reported behaviour to specific experiments.
"""

from __future__ import annotations

import sqlite3
import tempfile
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


TrialNamespaceRecord = TargetRecordDescriptor(
    "macos/trial/namespace",
    [
        ("string", "name"),
        ("string", "treatment_path"),
        ("varint", "compatibility_version"),
        ("varint", "experiments_rowid"),
        ("path", "source"),
    ],
)


class AppleTrialPlugin(Plugin):
    """Parse ``~/Library/Trial/v*/Database/triald.db``."""

    __namespace__ = "trial"

    GLOB = "Users/*/Library/Trial/v*/Database/triald.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No Trial database found")

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

    @export(record=TrialNamespaceRecord)
    def experiments(self) -> Iterator[TrialNamespaceRecord]:
        """One record per Trial namespace (experiment) the device is enrolled in."""
        for db_path in self._db_paths:
            conn, tmp = self._open(db_path)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        "SELECT name, treatmentPath, compatibilityVersion, experiments_rowid "
                        "FROM namespaces"
                    )
                except sqlite3.OperationalError as e:
                    self.target.log.warning("Error reading triald.db %s: %s", db_path, e)
                    continue
                for row in cur:
                    yield TrialNamespaceRecord(
                        name=row["name"] or "",
                        treatment_path=row["treatmentPath"] or "",
                        compatibility_version=row["compatibilityVersion"] or 0,
                        experiments_rowid=row["experiments_rowid"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            finally:
                conn.close()
                tmp.close()

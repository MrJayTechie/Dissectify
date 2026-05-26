"""Dock preferences plugin.

Reads ``~/Library/Preferences/com.apple.dock.plist`` — the per-user Dock
state. Beyond layout, the plist captures the user's recently used apps
and documents under ``recent-apps`` and similar keys. Useful for
attributing app launches to specific users and seeing the recency
heuristics the Dock used.
"""

from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


def _dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


DockItemRecord = TargetRecordDescriptor(
    "macos/dock/item",
    [
        ("string", "section"),
        ("string", "label"),
        ("string", "bundle_id"),
        ("string", "file_url"),
        ("varint", "tile_type"),
        ("varint", "guid"),
        ("path", "source"),
    ],
)


class MacOSDockPlugin(Plugin):
    """Parse ``~/Library/Preferences/com.apple.dock.plist``."""

    __namespace__ = "dock"

    GLOB = "Users/*/Library/Preferences/com.apple.dock.plist"

    def __init__(self, target):
        super().__init__(target)
        self._plists = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._plists:
            raise UnsupportedPluginError("No dock.plist found")

    @export(record=DockItemRecord)
    def items(self) -> Iterator[DockItemRecord]:
        """One record per Dock tile (persistent + recent apps and docs)."""
        for p in self._plists:
            try:
                with p.open("rb") as fh:
                    data = plistlib.load(fh)
            except Exception as e:
                self.target.log.warning("Error loading dock.plist %s: %s", p, e)
                continue
            for section in ("persistent-apps", "persistent-others", "recent-apps"):
                for entry in data.get(section, []) or []:
                    if not isinstance(entry, dict):
                        continue
                    td = entry.get("tile-data") or {}
                    label = td.get("file-label") or td.get("label") or ""
                    bundle_id = td.get("bundle-identifier") or ""
                    file_url = ""
                    fd = td.get("file-data") or {}
                    if isinstance(fd, dict):
                        file_url = fd.get("_CFURLString", "") or ""
                    yield DockItemRecord(
                        section=section,
                        label=label,
                        bundle_id=bundle_id,
                        file_url=file_url,
                        tile_type=entry.get("tile-type", 0)
                        if isinstance(entry.get("tile-type"), int) else 0,
                        guid=entry.get("GUID", 0) or 0,
                        source=p,
                        _target=self.target,
                    )

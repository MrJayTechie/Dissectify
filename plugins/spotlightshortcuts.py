from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SpotlightShortcutRecord = TargetRecordDescriptor(
    "macos/spotlightshortcuts/entries",
    [
        ("datetime", "ts_last_used"),
        ("string", "user"),
        ("string", "query"),
        ("string", "display_name"),
        ("string", "url"),
        ("path", "source"),
    ],
)


class MacOSSpotlightShortcutsPlugin(Plugin):
    """Plugin to parse macOS Spotlight learned-shortcut history.

    Records the user's Spotlight search queries and which result they
    selected. Each entry maps a typed query (e.g. ``mail``) to the URL
    Spotlight learned to open for it, with the timestamp of the last
    selection.

    Locations:
        ~/Library/Group Containers/group.com.apple.spotlight/com.apple.spotlight.Shortcuts.v*
        ~/Library/Application Support/com.apple.spotlight.Shortcuts        (legacy)
        ~/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.plist (legacy)
    """

    __namespace__ = "spotlightshortcuts"

    GLOBS = [
        "Users/*/Library/Group Containers/group.com.apple.spotlight/com.apple.spotlight.Shortcuts.v*",
        "Users/*/Library/Application Support/com.apple.spotlight.Shortcuts",
        "Users/*/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = []
        root = self.target.fs.path("/")
        for pattern in self.GLOBS:
            self._plist_paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No Spotlight shortcuts files found")

    @staticmethod
    def _user_from_path(path) -> str:
        parts = path.parts
        try:
            i = parts.index("Users")
            return parts[i + 1]
        except (ValueError, IndexError):
            return ""

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception as e:
            self.target.log.warning("Error reading Spotlight shortcuts %s: %s", path, e)
            return None

    @export(record=SpotlightShortcutRecord)
    def entries(self) -> Iterator[SpotlightShortcutRecord]:
        """Yield one record per learned Spotlight shortcut."""
        for path in self._plist_paths:
            data = self._read_plist(path)
            if not isinstance(data, dict):
                continue

            user = self._user_from_path(path)

            for query, payload in data.items():
                if not isinstance(payload, dict):
                    continue

                yield SpotlightShortcutRecord(
                    ts_last_used=payload.get("LAST_USED"),
                    user=user,
                    query=str(query),
                    display_name=payload.get("DISPLAY_NAME") or "",
                    url=payload.get("URL") or "",
                    source=path,
                    _target=self.target,
                )

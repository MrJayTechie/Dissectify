"""macOS Core Location daemon plugin.

Reads ``/private/var/db/locationd/clients.plist`` — the per-app
authorization record for Core Location. Each client entry lists:

- the bundle id / executable path requesting location
- the authorization decision (``Authorized``, ``Denied``, ``Restricted``)
- the requested accuracy and purpose string
- the dates the prompt was shown and the decision was made
- usage counters

Useful both to enumerate which apps had location access and to surface
malicious apps that managed to obtain it.
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


LocationdClientRecord = TargetRecordDescriptor(
    "macos/locationd/client",
    [
        ("datetime", "ts_registered"),
        ("datetime", "ts_authorized"),
        ("string", "bundle_id"),
        ("string", "executable_path"),
        ("string", "authorization"),
        ("string", "accuracy"),
        ("string", "purpose"),
        ("varint", "is_widget"),
        ("varint", "background_location"),
        ("path", "source"),
    ],
)


class MacOSLocationdPlugin(Plugin):
    """Parse ``/private/var/db/locationd/clients.plist``."""

    __namespace__ = "locationd"

    PLIST = "private/var/db/locationd/clients.plist"

    def __init__(self, target):
        super().__init__(target)
        self.path = self.target.fs.path("/") / self.PLIST

    def check_compatible(self) -> None:
        if not self.path.exists():
            raise UnsupportedPluginError("No locationd clients.plist found")

    @export(record=LocationdClientRecord)
    def clients(self) -> Iterator[LocationdClientRecord]:
        """One record per app that has requested Core Location access."""
        try:
            with self.path.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception as e:
            self.target.log.warning("Error loading locationd clients.plist: %s", e)
            return
        for ident, info in data.items():
            if not isinstance(info, dict):
                continue
            yield LocationdClientRecord(
                ts_registered=_dt(info.get("Registered")),
                ts_authorized=_dt(info.get("Authorized")),
                bundle_id=info.get("BundleId") or ident,
                executable_path=info.get("Executable") or info.get("BundlePath", "") or "",
                authorization=str(info.get("Authorization", "") or ""),
                accuracy=str(info.get("LocationAccuracy", "") or ""),
                purpose=info.get("LocationPurpose", "") or info.get("DescriptionKey", "") or "",
                is_widget=int(bool(info.get("Widget", False))),
                background_location=int(bool(info.get("BackgroundLocationEnabled", False))),
                source=self.path,
                _target=self.target,
            )

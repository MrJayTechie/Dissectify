"""macOS Lockdown plugin (paired iOS devices).

When an iPhone / iPad / Apple Watch is paired with this Mac, the
``lockdownd`` service stores a pairing-record plist at
``/private/var/db/lockdown/<UDID>.plist``. Each plist contains the iOS
device's serial number, ECID, paired-on date, the trust certificate
chain, and (until iOS 16+) the WiFi MAC address. Critical artifact for
"what phones touched this Mac" investigations.
"""

from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


LockdownDeviceRecord = TargetRecordDescriptor(
    "macos/lockdown/device",
    [
        ("string", "udid"),
        ("string", "device_name"),
        ("string", "product_type"),
        ("string", "product_version"),
        ("string", "serial_number"),
        ("string", "wifi_mac"),
        ("string", "bluetooth_mac"),
        ("string", "ecid"),
        ("string", "host_id"),
        ("string", "system_buid"),
        ("path", "source"),
    ],
)


class MacOSLockdownPlugin(Plugin):
    """Parse pairing records under ``/private/var/db/lockdown/*.plist``."""

    __namespace__ = "lockdown"

    GLOB = "private/var/db/lockdown/*.plist"

    def __init__(self, target):
        super().__init__(target)
        self._plists = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._plists:
            raise UnsupportedPluginError("No Lockdown pairing records found")

    # Sibling plists in /private/var/db/lockdown/ that AREN'T device pairings:
    # ``SystemConfiguration.plist`` (lockdownd's own state), the
    # ``Whitelist.plist`` (a list of cleared apps), and the ``escrow`` /
    # ``pair-records`` subdirectory metadata. Drop them so we only emit real
    # paired devices.
    _NON_PAIRING_PLISTS = frozenset({
        "SystemConfiguration.plist",
        "Whitelist.plist",
        "wgs.plist",
    })

    @export(record=LockdownDeviceRecord)
    def paired(self) -> Iterator[LockdownDeviceRecord]:
        """One record per paired iOS device — UDID, model, serial, MACs, ECID."""
        for p in self._plists:
            if p.name in self._NON_PAIRING_PLISTS:
                continue
            try:
                with p.open("rb") as fh:
                    data = plistlib.load(fh)
                udid = p.name[: -len(".plist")] if p.name.endswith(".plist") else p.name
                yield LockdownDeviceRecord(
                    udid=udid,
                    device_name=data.get("DeviceName", "") or "",
                    product_type=data.get("ProductType", "") or "",
                    product_version=data.get("ProductVersion", "") or "",
                    serial_number=data.get("SerialNumber", "") or "",
                    wifi_mac=data.get("WiFiAddress", "") or "",
                    bluetooth_mac=data.get("BluetoothAddress", "") or "",
                    ecid=str(data.get("UniqueChipID", "") or ""),
                    host_id=data.get("HostID", "") or "",
                    system_buid=data.get("SystemBUID", "") or "",
                    source=p,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing lockdown plist %s: %s", p, e)

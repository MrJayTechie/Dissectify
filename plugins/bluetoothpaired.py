"""Paired Bluetooth devices plugin.

Reads ``/Library/Preferences/com.apple.Bluetooth.plist`` — the system-wide
paired-device list. Compared to ``ble.devices_seen`` (which captures every
nearby BLE peripheral observed), this plist is only the *paired* devices
(AirPods, Apple TV remotes, paired keyboards/mice, Magic Trackpads, etc.)
including their last-seen and pairing-completed timestamps.
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


BluetoothPairedRecord = TargetRecordDescriptor(
    "macos/bluetooth/paired",
    [
        ("datetime", "ts_last_seen"),
        ("datetime", "ts_paired"),
        ("string", "address"),
        ("string", "name"),
        ("string", "vendor_id"),
        ("string", "product_id"),
        ("string", "services"),
        ("path", "source"),
    ],
)


def _dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


def _norm_addr(a):
    if not a:
        return ""
    if isinstance(a, str):
        return a
    if isinstance(a, (bytes, bytearray, memoryview)):
        return ":".join(f"{x:02x}" for x in bytes(a))
    return str(a)


class MacOSBluetoothPairedPlugin(Plugin):
    """Parse ``/Library/Preferences/com.apple.Bluetooth.plist``."""

    __namespace__ = "bluetoothpaired"

    PLIST = "Library/Preferences/com.apple.Bluetooth.plist"

    def __init__(self, target):
        super().__init__(target)
        self.path = self.target.fs.path("/") / self.PLIST

    def check_compatible(self) -> None:
        if not self.path.exists():
            raise UnsupportedPluginError("No com.apple.Bluetooth.plist found")

    @export(record=BluetoothPairedRecord)
    def devices(self) -> Iterator[BluetoothPairedRecord]:
        """One record per paired Bluetooth device with timestamps + vendor/product IDs."""
        try:
            with self.path.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception as e:
            self.target.log.warning("Error loading Bluetooth.plist: %s", e)
            return

        paired_keys = ("PairedDevices", "PersistentPortsClassic", "PersistentPortsLE")
        cache = data.get("DeviceCache") or {}
        ll_cache = data.get("LowEnergyDevices") or {}

        seen_addrs = set()
        for addr, info in cache.items():
            seen_addrs.add(addr)
            yield BluetoothPairedRecord(
                ts_last_seen=_dt(info.get("LastSeenTime") or info.get("LastInquiryUpdate")),
                ts_paired=_dt(info.get("PairTime") or info.get("LastBoundTime")),
                address=_norm_addr(addr),
                name=info.get("Name", "") or info.get("DefaultName", "") or "",
                vendor_id=str(info.get("VendorID", "") or ""),
                product_id=str(info.get("ProductID", "") or ""),
                services=",".join(
                    s for s in (info.get("Services", []) or [])
                    if isinstance(s, str)
                )[:500],
                source=self.path,
                _target=self.target,
            )
        for addr, info in ll_cache.items():
            if addr in seen_addrs:
                continue
            yield BluetoothPairedRecord(
                ts_last_seen=_dt(info.get("LastSeenTime")),
                ts_paired=_dt(info.get("PairTime")),
                address=_norm_addr(addr),
                name=info.get("Name", "") or "",
                vendor_id=str(info.get("VendorID", "") or ""),
                product_id=str(info.get("ProductID", "") or ""),
                services="",
                source=self.path,
                _target=self.target,
            )
        for key in paired_keys:
            for addr in data.get(key, []) or []:
                if addr in seen_addrs:
                    continue
                yield BluetoothPairedRecord(
                    ts_last_seen=None,
                    ts_paired=None,
                    address=_norm_addr(addr),
                    name="",
                    vendor_id="",
                    product_id="",
                    services="",
                    source=self.path,
                    _target=self.target,
                )

"""macOS SystemConfiguration plists — networking + persistence config.

Parses the four canonical plists under
``/Library/Preferences/SystemConfiguration/``:

- ``com.apple.airport.preferences.plist`` — known WiFi networks (BSSID,
  SSID, last joined date, channel, security type, hidden flag).
- ``NetworkInterfaces.plist`` — every network interface the system has
  ever known of, with its MAC address (`IOMACAddress`), built-in flag,
  user-visible name (`UserDefinedName`).
- ``preferences.plist`` — system network locations + hostname history.
- ``com.apple.alf.plist`` — application firewall configuration.
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


def _mac_bytes_to_str(b):
    if isinstance(b, (bytes, bytearray, memoryview)):
        return ":".join(f"{x:02x}" for x in bytes(b))
    return str(b) if b else ""


WiFiKnownRecord = TargetRecordDescriptor(
    "macos/sysconfig/wifi_known",
    [
        ("datetime", "ts_last_joined"),
        ("string", "ssid"),
        ("string", "bssid"),
        ("string", "security"),
        ("string", "channel"),
        ("varint", "hidden"),
        ("varint", "auto_join_disabled"),
        ("path", "source"),
    ],
)

NetworkInterfaceRecord = TargetRecordDescriptor(
    "macos/sysconfig/network_interface",
    [
        ("string", "bsd_name"),
        ("string", "user_name"),
        ("string", "mac_address"),
        ("varint", "active"),
        ("varint", "builtin"),
        ("string", "interface_type"),
        ("string", "iokit_path"),
        ("path", "source"),
    ],
)

NetworkLocationRecord = TargetRecordDescriptor(
    "macos/sysconfig/network_location",
    [
        ("string", "set_name"),
        ("string", "set_id"),
        ("varint", "is_current"),
        ("path", "source"),
    ],
)

FirewallSettingRecord = TargetRecordDescriptor(
    "macos/sysconfig/firewall_setting",
    [
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class MacOSSystemConfigPlugin(Plugin):
    """Parse the SystemConfiguration plists (known WiFi, MACs, locations, ALF)."""

    __namespace__ = "sysconfig"

    AIRPORT = "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
    AIRPORT_TAHOE = "Library/Preferences/com.apple.wifi.known-networks.plist"
    INTERFACES = "Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"
    PREFS = "Library/Preferences/SystemConfiguration/preferences.plist"
    ALF = "Library/Preferences/com.apple.alf.plist"

    def __init__(self, target):
        super().__init__(target)
        root = self.target.fs.path("/")
        self.airport_path = root / self.AIRPORT
        self.airport_tahoe_path = root / self.AIRPORT_TAHOE
        self.interfaces_path = root / self.INTERFACES
        self.prefs_path = root / self.PREFS
        self.alf_path = root / self.ALF

    def check_compatible(self) -> None:
        if not any(p.exists() for p in (
            self.airport_path, self.interfaces_path, self.prefs_path, self.alf_path,
        )):
            raise UnsupportedPluginError("No SystemConfiguration plists found")

    def _load(self, p):
        if not p.exists():
            return None
        try:
            with p.open("rb") as fh:
                return plistlib.load(fh)
        except Exception as e:
            self.target.log.warning("Error loading %s: %s", p, e)
            return None

    @export(record=WiFiKnownRecord)
    def wifi_known(self) -> Iterator[WiFiKnownRecord]:
        """One record per known WiFi network (SSID + BSSID + last-joined).

        Tahoe moved known-network storage out of
        ``airport.preferences.plist`` (which now only holds the device UUID
        and join policy) into ``com.apple.wifi.known-networks.plist``. We
        parse both and emit one record per entry."""
        # Legacy path (pre-Tahoe)
        data = self._load(self.airport_path)
        if data:
            for net in (data.get("KnownNetworks") or {}).values():
                yield WiFiKnownRecord(
                    ts_last_joined=_dt(net.get("LastConnected") or net.get("JoinedByUserAt")),
                    ssid=net.get("SSIDString") or net.get("SSID", "") or "",
                    bssid=net.get("BSSID", "") or "",
                    security=net.get("SecurityType") or net.get("Security", "") or "",
                    channel=str(net.get("Channel", "")),
                    hidden=int(bool(net.get("Hidden", False))),
                    auto_join_disabled=int(bool(net.get("AutoJoinDisabled", False))),
                    source=self.airport_path,
                    _target=self.target,
                )
        # Tahoe path
        data = self._load(self.airport_tahoe_path)
        if not data:
            return
        # Schema: top-level keys are "wifi.network.ssid.<ssid>" or similar
        for key, net in data.items():
            if not isinstance(net, dict):
                continue
            yield WiFiKnownRecord(
                ts_last_joined=_dt(
                    net.get("JoinedByUserAt")
                    or net.get("UpdatedAt")
                    or net.get("AddedAt")
                ),
                ssid=net.get("SSID", "") or key,
                bssid=net.get("BSSID", "") or "",
                security=str(net.get("SupportedSecurityTypes", "") or ""),
                channel=str(net.get("Channel", "")),
                hidden=int(bool(net.get("Hidden", False))),
                auto_join_disabled=int(bool(net.get("AutoJoinDisabled", False))),
                source=self.airport_tahoe_path,
                _target=self.target,
            )

    @export(record=NetworkInterfaceRecord)
    def network_interfaces(self) -> Iterator[NetworkInterfaceRecord]:
        """One record per network interface — MAC + type + IOKit path."""
        data = self._load(self.interfaces_path)
        if not data:
            return
        for iface in data.get("Interfaces", []) or []:
            mac = iface.get("IOMACAddress")
            yield NetworkInterfaceRecord(
                bsd_name=iface.get("BSD Name", "") or "",
                user_name=iface.get("SCNetworkInterfaceInfo", {}).get(
                    "UserDefinedName", iface.get("UserDefinedName", "") or "",
                ),
                mac_address=_mac_bytes_to_str(mac),
                active=int(bool(iface.get("Active", False))),
                builtin=int(bool(iface.get("IOBuiltin", False))),
                interface_type=iface.get("SCNetworkInterfaceType", "") or "",
                iokit_path=iface.get("IOPathMatch", "") or "",
                source=self.interfaces_path,
                _target=self.target,
            )

    @export(record=NetworkLocationRecord)
    def network_locations(self) -> Iterator[NetworkLocationRecord]:
        """One record per saved network location (Home/Work/etc) + current pointer."""
        data = self._load(self.prefs_path)
        if not data:
            return
        current = data.get("CurrentSet", "") or ""
        sets = data.get("Sets") or {}
        for sid, payload in sets.items():
            yield NetworkLocationRecord(
                set_name=payload.get("UserDefinedName", "") or "",
                set_id=sid,
                is_current=int(current.endswith(sid)),
                source=self.prefs_path,
                _target=self.target,
            )

    @export(record=FirewallSettingRecord)
    def firewall(self) -> Iterator[FirewallSettingRecord]:
        """One record per top-level Application Firewall setting in alf.plist."""
        data = self._load(self.alf_path)
        if not data:
            return
        for k, v in data.items():
            yield FirewallSettingRecord(
                key=str(k),
                value=str(v)[:500],
                source=self.alf_path,
                _target=self.target,
            )

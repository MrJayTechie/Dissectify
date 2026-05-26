"""VPN / NetworkExtension config plugin.

Reads ``/Library/Preferences/com.apple.networkextension.plist`` — the
system-wide list of configured Network Extension instances (mostly VPN
configurations, also content-filter providers and DNS proxies). Each
entry has a UUID, the provider bundle id, server address, and the
on-demand / always-on flags.
"""

from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


VPNConfigRecord = TargetRecordDescriptor(
    "macos/vpn/config",
    [
        ("string", "name"),
        ("string", "uuid"),
        ("string", "provider_bundle"),
        ("string", "provider_type"),
        ("string", "server_address"),
        ("varint", "always_on"),
        ("varint", "disconnect_on_sleep"),
        ("varint", "is_enabled"),
        ("path", "source"),
    ],
)


class MacOSVPNConfigPlugin(Plugin):
    """Parse ``/Library/Preferences/com.apple.networkextension.plist``."""

    __namespace__ = "vpn"

    PLIST = "Library/Preferences/com.apple.networkextension.plist"

    def __init__(self, target):
        super().__init__(target)
        self.path = self.target.fs.path("/") / self.PLIST

    def check_compatible(self) -> None:
        if not self.path.exists():
            raise UnsupportedPluginError("No networkextension.plist found")

    @export(record=VPNConfigRecord)
    def configs(self) -> Iterator[VPNConfigRecord]:
        """One record per configured VPN / NetworkExtension instance."""
        try:
            with self.path.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception as e:
            self.target.log.warning("Error loading networkextension.plist: %s", e)
            return
        for cfg in data.get("$objects", []) or []:
            if not isinstance(cfg, dict):
                continue
        for uuid, cfg in (data.get("Configurations") or {}).items():
            if not isinstance(cfg, dict):
                continue
            yield VPNConfigRecord(
                name=cfg.get("Name", "") or "",
                uuid=uuid,
                provider_bundle=cfg.get("Plugin") or cfg.get("ProviderBundleIdentifier", "") or "",
                provider_type=cfg.get("ProviderType", "") or "",
                server_address=cfg.get("Server", "") or "",
                always_on=int(bool(cfg.get("AlwaysOn", False))),
                disconnect_on_sleep=int(bool(cfg.get("DisconnectOnSleep", False))),
                is_enabled=int(bool(cfg.get("Enabled", True))),
                source=self.path,
                _target=self.target,
            )

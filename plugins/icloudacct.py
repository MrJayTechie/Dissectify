"""iCloud (MobileMe) accounts plugin.

Reads ``~/Library/Preferences/MobileMeAccounts.plist`` — the per-user
record of every iCloud account configured on this Mac with its Apple ID,
display name, enabled services (CloudKit, iCloud Drive, Mail, etc.), and
linked device set.
"""

from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ICloudAccountRecord = TargetRecordDescriptor(
    "macos/icloud/account",
    [
        ("string", "account_dsid"),
        ("string", "account_id"),
        ("string", "display_name"),
        ("string", "log_in_id"),
        ("string", "services"),
        ("varint", "logged_in"),
        ("path", "source"),
    ],
)


class MacOSiCloudAccountsPlugin(Plugin):
    """Parse ``~/Library/Preferences/MobileMeAccounts.plist``."""

    __namespace__ = "icloudaccounts"

    GLOB = "Users/*/Library/Preferences/MobileMeAccounts.plist"

    def __init__(self, target):
        super().__init__(target)
        self._plists = list(self.target.fs.path("/").glob(self.GLOB))

    def check_compatible(self) -> None:
        if not self._plists:
            raise UnsupportedPluginError("No MobileMeAccounts.plist found")

    @export(record=ICloudAccountRecord)
    def accounts(self) -> Iterator[ICloudAccountRecord]:
        """One record per iCloud account configured (Apple ID + enabled services)."""
        for p in self._plists:
            try:
                with p.open("rb") as fh:
                    data = plistlib.load(fh)
            except Exception as e:
                self.target.log.warning("Error loading MobileMeAccounts.plist %s: %s", p, e)
                continue
            for acct in data.get("Accounts", []) or []:
                services_enabled = [
                    s.get("Name", "")
                    for s in (acct.get("Services") or [])
                    if isinstance(s, dict) and s.get("Enabled")
                ]
                yield ICloudAccountRecord(
                    account_dsid=str(acct.get("AccountDSID", "") or ""),
                    account_id=acct.get("AccountID", "") or "",
                    display_name=acct.get("DisplayName", "") or "",
                    log_in_id=acct.get("LogInIDAlias", "") or "",
                    services=",".join(services_enabled),
                    logged_in=int(bool(acct.get("LoggedIn", False))),
                    source=p,
                    _target=self.target,
                )

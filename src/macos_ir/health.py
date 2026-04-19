"""Collection health engine — validates a Velociraptor macOS collection.

Checks artifact presence, SQLite WAL completeness, FDA/SIP inference,
and provides actionable recommendations.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Artifact registry: 70 YAML collectors -> expected paths in uploads/auto/
# ──────────────────────────────────────────────────────────────────────────────

ARTIFACT_REGISTRY = {
    # ── Browsers & Web ──
    "ChromiumBrowsers": {
        "category": "Browsers",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/Application Support/Google/Chrome/Default/History",
            "Users/*/Library/Application Support/Microsoft Edge/Default/History",
            "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
            "Users/*/Library/Application Support/Chromium/Default/History",
            "Users/*/Library/Application Support/com.operasoftware.Opera/Default/History",
            "Users/*/Library/Application Support/Vivaldi/Default/History",
        ],
        "check": "any",
    },
    "FirefoxFiles": {
        "category": "Browsers",
        "privilege": "USER",
        "paths": ["Users/*/Library/Application Support/Firefox/Profiles"],
        "check": "dir",
    },
    "SafariFiles": {
        "category": "Browsers",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Safari"],
        "check": "dir",
    },
    "cookies": {
        "category": "Browsers",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Cookies",
            "Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies",
        ],
        "check": "dir_any",
    },
    # ── Communications ──
    "iMessage": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Messages/chat.db"],
        "check": "per_user",
    },
    "CallHistory": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata"],
        "check": "per_user",
    },
    "FaceTime": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3"],
        "check": "per_user",
    },
    "AddressBook": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Application Support/AddressBook"],
        "check": "dir",
    },
    "AppleMail": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Mail"],
        "check": "dir",
    },
    "Notifications": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db",
        ],
        "check": "per_user",
    },
    "AppleNotes": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        ],
        "check": "per_user",
    },
    "notes": {
        "category": "Communications",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Group Containers/group.com.apple.notes",
            "Users/*/Library/Containers/com.apple.Notes/Data/Library/Notes",
        ],
        "check": "dir_any",
    },
    # ── User Activity ──
    "KnowledgeC": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "private/var/db/CoreDuet/Knowledge/knowledgeC.db",
            "Users/*/Library/Application Support/Knowledge/knowledgeC.db",
        ],
        "check": "any",
    },
    "Interactions": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": ["private/var/db/CoreDuet/People/interactionC.db"],
        "check": "exact",
    },
    "Biomes": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Biome", "private/var/db/biome"],
        "check": "dir_any",
    },
    "WifiIntelligence": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db",
        ],
        "check": "per_user",
    },
    "Powerlogs": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL",
        ],
        "check": "exact",
    },
    "ScreenTime": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": ["private/var/folders"],
        "check": "screentime",
    },
    "Reminders": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Group Containers/group.com.apple.reminders/Container_v1/Stores",
        ],
        "check": "dir",
    },
    "Calendars": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Calendars"],
        "check": "dir",
    },
    "FindMy": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Caches/com.apple.findmy.fmipcore/Items.data",
            "Users/*/Library/Caches/com.apple.findmy.fmfcore/FriendCacheData.data",
        ],
        "check": "any",
    },
    "SpotlightShortCuts": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Application Support/com.apple.spotlight",
        ],
        "check": "dir",
    },
    # ── Persistence & Execution ──
    "Autostart": {
        "category": "Persistence",
        "privilege": "USER",
        "paths": [
            "Library/LaunchAgents",
            "Library/LaunchDaemons",
            "System/Library/LaunchAgents",
            "System/Library/LaunchDaemons",
            "Users/*/Library/LaunchAgents",
        ],
        "check": "dir_any",
    },
    "KernelExtensions": {
        "category": "Persistence",
        "privilege": "USER",
        "paths": [
            "System/Library/Extensions",
            "Library/Extensions",
            "Library/SystemExtensions",
        ],
        "check": "dir_any",
    },
    "Applications": {
        "category": "Persistence",
        "privilege": "USER",
        "paths": ["Applications"],
        "check": "dir",
    },
    "LaunchPad": {
        "category": "Persistence",
        "privilege": "FDA",
        "paths": ["private/var/folders"],
        "check": "launchpad",
    },
    # ── Security & Privacy ──
    "TCC": {
        "category": "Security",
        "privilege": "FDA",
        "paths": [
            "Library/Application Support/com.apple.TCC/TCC.db",
            "Users/*/Library/Application Support/com.apple.TCC/TCC.db",
        ],
        "check": "any",
    },
    "FirewallConfiguration": {
        "category": "Security",
        "privilege": "USER",
        "paths": [
            "etc/pf.conf",
            "private/etc/pf.conf",
            "usr/libexec/ApplicationFirewall/com.apple.alf.plist",
            "Library/Preferences/com.apple.alf.plist",
        ],
        "check": "any",
    },
    "KeyChain": {
        "category": "Security",
        "privilege": "FDA+SIP",
        "paths": [
            "Users/*/Library/Keychains",
            "Library/Keychains/System.keychain",
        ],
        "check": "any_mixed",
    },
    "ManagedDeviceProfile": {
        "category": "Security",
        "privilege": "ROOT",
        "paths": ["private/var/db/ConfigurationProfiles"],
        "check": "dir",
    },
    "xpdb": {
        "category": "Security",
        "privilege": "SIP",
        "paths": ["private/var/protected/xprotect/db"],
        "check": "dir",
    },
    "Sudoers": {
        "category": "Security",
        "privilege": "USER",
        "paths": ["etc/sudoers"],
        "check": "exact",
    },
    "sudolastrun": {
        "category": "Security",
        "privilege": "ROOT",
        "paths": ["private/var/db/sudo/ts"],
        "check": "dir",
    },
    # ── System Configuration ──
    "OSName": {
        "category": "System",
        "privilege": "USER",
        "paths": ["System/Library/CoreServices/SystemVersion.plist"],
        "check": "exact",
    },
    "OSInstallationDate": {
        "category": "System",
        "privilege": "USER",
        "paths": ["private/var/db/%2EAppleSetupDone"],
        "check": "exact_or_alt",
        "alt_paths": ["private/var/db/.AppleSetupDone"],
    },
    "Users": {
        "category": "System",
        "privilege": "ROOT",
        "paths": ["private/var/db/dslocal/nodes/Default/users"],
        "check": "dir",
    },
    "localtime": {
        "category": "System",
        "privilege": "USER",
        "paths": ["etc/localtime"],
        "check": "exact",
    },
    "hosts": {
        "category": "System",
        "privilege": "USER",
        "paths": ["etc/hosts"],
        "check": "exact",
    },
    "etcFolder": {
        "category": "System",
        "privilege": "USER",
        "paths": ["private/etc"],
        "check": "dir",
    },
    "SharedFolder": {
        "category": "System",
        "privilege": "ROOT",
        "paths": ["private/var/db/dslocal/nodes/Default/sharepoints"],
        "check": "dir",
    },
    "DHCPLease": {
        "category": "System",
        "privilege": "FDA",
        "paths": ["private/var/db/dhcpclient/leases"],
        "check": "dir",
    },
    "InternetAccounts": {
        "category": "System",
        "privilege": "USER",
        "paths": ["Users/*/Library/Accounts"],
        "check": "dir",
    },
    "LibraryPreferences": {
        "category": "System",
        "privilege": "USER",
        "paths": ["Users/*/Library/Preferences", "Library/Preferences"],
        "check": "dir_any",
    },
    # ── Logs ──
    "AlternateLog": {
        "category": "Logs",
        "privilege": "USER",
        "paths": ["private/var/log", "var/log"],
        "check": "dir_any",
    },
    "CrashReporter": {
        "category": "Logs",
        "privilege": "USER",
        "paths": ["Users/*/Library/Application Support/CrashReporter"],
        "check": "dir",
    },
    "PrintJobs": {
        "category": "Logs",
        "privilege": "USER",
        "paths": ["private/var/spool/cups"],
        "check": "dir",
    },
    # ── File System ──
    "DSStore": {
        "category": "Filesystem",
        "privilege": "USER",
        "paths": ["Users"],
        "check": "dsstore",
    },
    "FsEvents": {
        "category": "Filesystem",
        "privilege": "USER",
        "paths": [
            "%2Efseventsd",
            ".fseventsd",
            "System/Volumes/Data/%2Efseventsd",
            "System/Volumes/Data/.fseventsd",
            "private/var/db/fseventsd",
        ],
        "check": "dir_any",
    },
    "DocumentRevisions": {
        "category": "Filesystem",
        "privilege": "USER",
        "paths": [
            "%2EDocumentRevisions-V100",
            ".DocumentRevisions-V100",
            "System/Volumes/Data/%2EDocumentRevisions-V100",
            "System/Volumes/Data/.DocumentRevisions-V100",
        ],
        "check": "dir_any",
    },
    "Trash": {
        "category": "Filesystem",
        "privilege": "USER",
        "paths": [
            "Users/*/%2ETrash",
            "Users/*/.Trash",
        ],
        "check": "dir_any",
    },
    "QuickLook": {
        "category": "Filesystem",
        "privilege": "FDA",
        "paths": ["private/var/folders"],
        "check": "quicklook",
    },
    # ── Apps & Documents ──
    "ApplePayWallet": {
        "category": "Apps",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Passes/passes23.sqlite"],
        "check": "per_user",
    },
    "InstallHistory": {
        "category": "Apps",
        "privilege": "USER",
        "paths": ["Library/Receipts/InstallHistory.plist"],
        "check": "exact",
    },
    "SoftwareInstallationUpdates": {
        "category": "Apps",
        "privilege": "USER",
        "paths": [
            "Library/Receipts/InstallHistory.plist",
            "Library/Preferences/com.apple.SoftwareUpdate.plist",
        ],
        "check": "any",
    },
    "MicrosoftOfficeMRU": {
        "category": "Apps",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Containers/com.microsoft.Word"],
        "check": "dir",
    },
    "Applist": {
        "category": "Apps",
        "privilege": "ROOT",
        "paths": [
            "Users/*/Library/Application Support/com.apple.spotlight/appList.dat",
        ],
        "check": "per_user",
    },
    # ── Network & Remote ──
    "SSHHost": {
        "category": "Network",
        "privilege": "USER",
        "paths": [
            "Users/*/%2Essh/known_hosts",
            "Users/*/.ssh/known_hosts",
        ],
        "check": "any",
    },
    "ard": {
        "category": "Network",
        "privilege": "SIP",
        "paths": ["private/var/db/RemoteManagement/caches"],
        "check": "dir",
    },
    "msrdc": {
        "category": "Network",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Containers/com.microsoft.rdc.macos"],
        "check": "dir",
    },
    "ScreenSharing": {
        "category": "Network",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Containers/com.apple.ScreenSharing",
        ],
        "check": "dir",
    },
    "FavoriteVolumes": {
        "category": "Network",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/Application Support/com.apple.sharedfilelist",
        ],
        "check": "dir",
    },
    "lockdown": {
        "category": "Network",
        "privilege": "FDA",
        "paths": ["private/var/db/lockdown"],
        "check": "dir",
    },
    # ── Shell & State ──
    "ShellHistoryAndSessions": {
        "category": "Shell",
        "privilege": "USER",
        "paths": [
            "Users/*/%2Ezsh_history",
            "Users/*/.zsh_history",
            "Users/*/%2Ebash_history",
            "Users/*/.bash_history",
        ],
        "check": "any",
    },
    "utmpx": {
        "category": "Shell",
        "privilege": "USER",
        "paths": ["private/var/run/utmpx"],
        "check": "exact",
    },
    "SavedState": {
        "category": "Shell",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/Saved Application State",
            "Users/*/Library/Daemon Containers",
        ],
        "check": "dir_any",
    },
    "TerminalState": {
        "category": "Shell",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/Saved Application State/com.apple.Terminal.savedState",
        ],
        "check": "dir",
    },
    "KeyboardDictionary": {
        "category": "Shell",
        "privilege": "USER",
        "paths": ["Users/*/Library/Spelling"],
        "check": "dir",
    },
    # ── Cloud & Devices ──
    "iCloud": {
        "category": "Cloud",
        "privilege": "FDA",
        "paths": [
            "Users/*/Library/Application Support/CloudDocs/session/db/server.db",
            "Users/*/Library/Application Support/iCloud/Accounts",
        ],
        "check": "any",
    },
    "iCloudLocalStorage": {
        "category": "Cloud",
        "privilege": "USER",
        "paths": ["Users/*/Library/Mobile Documents"],
        "check": "dir",
    },
    "iDeviceBackup": {
        "category": "Cloud",
        "privilege": "FDA",
        "paths": ["Users/*/Library/Application Support/MobileSync/Backup"],
        "check": "dir",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# SQLite WAL check
# ──────────────────────────────────────────────────────────────────────────────

SQLITE_WAL_ARTIFACTS = {
    "KnowledgeC (system)": "private/var/db/CoreDuet/Knowledge/knowledgeC.db",
    "KnowledgeC (user)": "Users/*/Library/Application Support/Knowledge/knowledgeC.db",
    "TCC (system)": "Library/Application Support/com.apple.TCC/TCC.db",
    "TCC (user)": "Users/*/Library/Application Support/com.apple.TCC/TCC.db",
    "Interactions": "private/var/db/CoreDuet/People/interactionC.db",
    "iMessage": "Users/*/Library/Messages/chat.db",
    "CallHistory": "Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata",
    "FaceTime": "Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3",
    "AppleNotes": "Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
    "Powerlogs": "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL",
    "WifiIntelligence": "Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db",
    "Notifications": "Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db",
    "ApplePayWallet": "Users/*/Library/Passes/passes23.sqlite",
    "SoftwareUpdates": "Users/*/Library/Caches/com.apple.appstoreagent/storeSystem.db",
    "msrdc": "Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite",
}

# ──────────────────────────────────────────────────────────────────────────────
# FDA / SIP indicators
# ──────────────────────────────────────────────────────────────────────────────

FDA_INDICATORS = [
    "KnowledgeC",
    "Interactions",
    "TCC",
    "Biomes",
    "iMessage",
    "SafariFiles",
    "AppleNotes",
    "Notifications",
    "Powerlogs",
    "WifiIntelligence",
]

SIP_BLOCKED = ["xpdb"]
SIP_PARTIAL = {"KeyChain": "private/var/db/SystemKey"}

MISSING_REASONS = {
    "ChromiumBrowsers": "No Chromium-based browser installed",
    "FirefoxFiles": "Firefox not installed",
    "SafariFiles": "FDA not granted, or Safari data wiped",
    "cookies": "FDA not granted, or no cookies stored",
    "iMessage": "iMessage not configured, or FDA not granted",
    "CallHistory": "No phone/FaceTime calls, or FDA not granted",
    "FaceTime": "FaceTime not used, or FDA not granted",
    "AddressBook": "No contacts, or FDA not granted",
    "AppleMail": "Mail.app not used, or FDA not granted",
    "Notifications": "FDA not granted",
    "AppleNotes": "No Apple Notes, or FDA not granted",
    "notes": "No Apple Notes (older path), or FDA not granted",
    "KnowledgeC": "FDA not granted (key indicator)",
    "Interactions": "FDA not granted (key indicator)",
    "Biomes": "FDA not granted (key indicator)",
    "WifiIntelligence": "No WiFi intelligence data, or FDA not granted",
    "Powerlogs": "FDA not granted",
    "ScreenTime": "ScreenTime disabled",
    "Reminders": "No Reminders data, or FDA not granted",
    "Calendars": "No calendar data",
    "FindMy": "FindMy data not cached",
    "SpotlightShortCuts": "No Spotlight shortcut data",
    "Autostart": "Should always be present — possible collection error",
    "KernelExtensions": "Should always be present — possible collection error",
    "Applications": "Should always be present — possible collection error",
    "LaunchPad": "FDA not granted",
    "TCC": "FDA not granted (key indicator)",
    "FirewallConfiguration": "Firewall config not found",
    "KeyChain": "FDA not granted, or keychain files missing",
    "ManagedDeviceProfile": "No MDM profiles (not enterprise-managed)",
    "xpdb": "SIP-blocked (expected on live system)",
    "Sudoers": "Should always be present — possible collection error",
    "sudolastrun": "sudo never used",
    "OSName": "Should always be present — possible collection error",
    "OSInstallationDate": ".AppleSetupDone not found",
    "Users": "Should always be present — possible collection error",
    "localtime": "Should always be present — possible collection error",
    "hosts": "Should always be present — possible collection error",
    "etcFolder": "Should always be present — possible collection error",
    "SharedFolder": "No SMB/AFP share points configured",
    "DHCPLease": "No DHCP leases",
    "InternetAccounts": "No internet accounts configured",
    "LibraryPreferences": "Should always be present — possible collection error",
    "AlternateLog": "Should always be present — possible collection error",
    "CrashReporter": "No crash reports",
    "PrintJobs": "No print job history",
    "DSStore": "No .DS_Store files found",
    "FsEvents": "No FSEvents data",
    "DocumentRevisions": "Versions database empty or purged",
    "Trash": "Trash is empty",
    "QuickLook": "QuickLook cache empty or purged",
    "ApplePayWallet": "Apple Pay not configured, or FDA not granted",
    "InstallHistory": "Should always be present — possible collection error",
    "SoftwareInstallationUpdates": "Should always be present — possible collection error",
    "MicrosoftOfficeMRU": "Microsoft Office not installed",
    "Applist": "Spotlight applist not found",
    "SSHHost": "No SSH connections made",
    "ard": "Apple Remote Desktop never enabled",
    "msrdc": "Microsoft Remote Desktop not installed",
    "ScreenSharing": "Screen Sharing never used",
    "FavoriteVolumes": "No Finder sidebar favorites",
    "lockdown": "No iOS device ever paired",
    "ShellHistoryAndSessions": "No shell history",
    "utmpx": "No login records",
    "SavedState": "No saved application state",
    "TerminalState": "Terminal no longer saves state on macOS 15",
    "KeyboardDictionary": "No custom dictionary words",
    "iCloud": "No iCloud data, or FDA not granted",
    "iCloudLocalStorage": "No iCloud Drive local files",
    "iDeviceBackup": "No local iPhone/iPad backups",
}


# ──────────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────────

class CollectionHealth:
    """Validate a Velociraptor macOS collection directory."""

    def __init__(self, collection_dir: str | Path):
        self.collection_dir = Path(collection_dir)
        self.uploads_auto = self._find_uploads_auto()
        self.users: list[str] = []
        self.metadata: dict = {}

    def _find_uploads_auto(self) -> Path:
        p = self.collection_dir
        if (p / "uploads" / "auto").is_dir():
            return p / "uploads" / "auto"
        if p.name == "auto" and (p / "Users").is_dir():
            self.collection_dir = p.parent.parent
            return p
        if (p / "auto").is_dir():
            self.collection_dir = p.parent
            return p / "auto"
        raise FileNotFoundError(f"Cannot find uploads/auto/ under {p}")

    def discover_users(self) -> list[str]:
        users_dir = self.uploads_auto / "Users"
        if not users_dir.is_dir():
            return []
        self.users = sorted([
            d.name for d in users_dir.iterdir()
            if d.is_dir() and d.name not in ("Shared", ".localized", "%2Elocalized")
        ])
        return self.users

    def load_metadata(self) -> dict:
        result = {
            "hostname": "UNKNOWN",
            "os_version": "",
            "collection_date": "",
            "duration_seconds": 0,
            "total_files": 0,
            "total_bytes": 0,
            "total_rows": 0,
            "artifacts_with_results": [],
        }

        ci_path = self.collection_dir / "client_info.json"
        if ci_path.exists():
            try:
                with open(ci_path) as f:
                    ci = json.load(f)
                result["hostname"] = ci.get("Hostname", ci.get("hostname", "UNKNOWN"))
                result["fqdn"] = ci.get("Fqdn", ci.get("fqdn", ""))
                result["architecture"] = ci.get("Architecture", ci.get("architecture", ""))
                result["os"] = ci.get("OS", ci.get("os", ""))
                result["kernel"] = ci.get("KernelVersion", ci.get("kernel_version", ""))
                os_info = ci.get("os_info", {})
                if os_info:
                    result["os_version"] = (
                        f"{os_info.get('system', '')} {os_info.get('release', '')} "
                        f"({os_info.get('machine', '')})"
                    )
            except Exception:
                pass

        cc_path = self.collection_dir / "collection_context.json"
        if cc_path.exists():
            try:
                with open(cc_path) as f:
                    cc = json.load(f)
                ts = cc.get("create_time", 0)
                if ts:
                    try:
                        if ts > 1e18:
                            ts_sec = ts / 1e9
                        elif ts > 1e15:
                            ts_sec = ts / 1e6
                        else:
                            ts_sec = ts
                        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                        result["collection_date"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        pass
                result["total_rows"] = cc.get("total_collected_rows", 0)
                result["total_bytes"] = cc.get("total_uploaded_bytes", 0)
                result["total_files"] = cc.get("total_uploaded_files", 0)
                result["artifacts_with_results"] = cc.get("artifacts_with_results", [])
                execution_duration = cc.get("execution_duration", 0)
                if execution_duration:
                    result["duration_seconds"] = execution_duration / 1_000_000_000
            except Exception:
                pass

        sv_path = self.uploads_auto / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
        if sv_path.exists():
            try:
                import plistlib
                with open(sv_path, "rb") as f:
                    sv = plistlib.load(f)
                result["os_version"] = (
                    f"{sv.get('ProductName', 'macOS')} "
                    f"{sv.get('ProductUserVisibleVersion', '')} "
                    f"({sv.get('ProductBuildVersion', '')})"
                )
            except Exception:
                pass

        self.metadata = result
        return result

    # ── Path helpers ──

    def _resolve_paths(self, pattern: str) -> list[Path]:
        if "Users/*" in pattern:
            results = []
            for user in self.users:
                resolved = pattern.replace("Users/*", f"Users/{user}", 1)
                results.append(self.uploads_auto / resolved)
            return results
        if "*" in pattern:
            try:
                return list(self.uploads_auto.glob(pattern))[:20]
            except Exception:
                return []
        return [self.uploads_auto / pattern]

    def _path_exists(self, p: Path) -> bool:
        return p.exists() or p.is_symlink()

    def _dir_has_files(self, d: Path) -> bool:
        if not d.is_dir():
            return False
        try:
            return any(True for _ in d.iterdir())
        except PermissionError:
            return False

    # ── Checks ──

    def check_artifact_presence(self) -> dict:
        results = {}
        for name, spec in ARTIFACT_REGISTRY.items():
            check = spec.get("check", "any")
            paths = spec["paths"]
            found_count = 0
            checked = 0

            if check in ("exact", "per_user", "any", "any_mixed", "dir_any"):
                for p in paths:
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if check == "dir" and self._dir_has_files(rp):
                            found_count += 1
                        elif check in ("dir_any", "any_mixed"):
                            if self._path_exists(rp) or self._dir_has_files(rp):
                                found_count += 1
                        elif self._path_exists(rp):
                            found_count += 1

            elif check == "exact_or_alt":
                for p in paths + spec.get("alt_paths", []):
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._path_exists(rp):
                            found_count += 1

            elif check == "dir":
                for p in paths:
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._dir_has_files(rp):
                            found_count += 1

            elif check in ("screentime", "launchpad", "quicklook", "dsstore"):
                checked = 1
                base = self.uploads_auto / paths[0]
                if check == "dsstore":
                    base = self.uploads_auto / "Users"
                    if base.is_dir():
                        for _ in base.rglob("*DS_Store"):
                            found_count = 1
                            break
                elif base.is_dir():
                    targets = {
                        "screentime": "com.apple.ScreenTimeAgent",
                        "launchpad": "com.apple.dock.launchpad",
                        "quicklook": "com.apple.QuickLook.thumbnailcache",
                    }
                    target = targets.get(check, "")
                    try:
                        for root, dirs, files in os.walk(str(base)):
                            if target in root:
                                found_count = 1
                                break
                            depth = root.replace(str(base), "").count(os.sep)
                            if depth > 5:
                                dirs.clear()
                    except Exception:
                        pass

            results[name] = {
                "status": "PRESENT" if found_count > 0 else "MISSING",
                "found": found_count,
                "checked": checked,
                "category": spec["category"],
                "privilege": spec["privilege"],
            }

        return results

    def check_wal_completeness(self) -> dict:
        results = {}
        for label, db_pattern in SQLITE_WAL_ARTIFACTS.items():
            resolved = self._resolve_paths(db_pattern)
            wal_resolved = self._resolve_paths(db_pattern + "-wal")
            shm_resolved = self._resolve_paths(db_pattern + "-shm")

            for i, db_path in enumerate(resolved):
                wal_path = wal_resolved[i] if i < len(wal_resolved) else None
                shm_path = shm_resolved[i] if i < len(shm_resolved) else None

                db_exists = self._path_exists(db_path) if db_path else False
                if not db_exists:
                    continue

                wal_exists = self._path_exists(wal_path) if wal_path else False
                shm_exists = self._path_exists(shm_path) if shm_path else False

                entry_label = label
                if "Users/*" in db_pattern and self.users:
                    user_idx = i % len(self.users) if self.users else 0
                    if user_idx < len(self.users):
                        entry_label = f"{label} ({self.users[user_idx]})"

                if db_exists and wal_exists and shm_exists:
                    status = "COMPLETE"
                elif db_exists and wal_exists:
                    status = "SHM_MISSING"
                elif db_exists:
                    status = "WAL_MISSING"
                else:
                    status = "DB_ONLY"

                wal_size = db_size = 0
                try:
                    db_size = db_path.stat().st_size
                    if wal_exists:
                        wal_size = wal_path.stat().st_size
                except Exception:
                    pass

                results[entry_label] = {
                    "status": status,
                    "db": db_exists,
                    "wal": wal_exists,
                    "shm": shm_exists,
                    "db_size": db_size,
                    "wal_size": wal_size,
                }

        return results

    def infer_fda_status(self, artifact_results: dict) -> dict:
        present = missing = 0
        indicators = {}
        for name in FDA_INDICATORS:
            is_present = artifact_results.get(name, {}).get("status") == "PRESENT"
            indicators[name] = is_present
            if is_present:
                present += 1
            else:
                missing += 1

        total = len(FDA_INDICATORS)
        if present >= 8:
            status, confidence = "GRANTED", "HIGH"
        elif present >= 5:
            status, confidence = "LIKELY_GRANTED", "MEDIUM"
        elif missing >= 8:
            status, confidence = "NOT_GRANTED", "HIGH"
        elif missing >= 5:
            status, confidence = "LIKELY_NOT_GRANTED", "MEDIUM"
        else:
            status, confidence = "INCONCLUSIVE", "LOW"

        return {
            "status": status,
            "confidence": confidence,
            "present": present,
            "missing": missing,
            "total": total,
            "indicators": indicators,
        }

    def generate_recommendations(self, artifact_results: dict, wal_results: dict, fda: dict) -> list[dict]:
        recs = []
        present = sum(1 for v in artifact_results.values() if v["status"] == "PRESENT")
        total = len(artifact_results)

        if fda["status"] in ("NOT_GRANTED", "LIKELY_NOT_GRANTED"):
            recs.append({
                "level": "CRITICAL",
                "message": (
                    f"FDA likely NOT granted ({fda['missing']}/{fda['total']} protected artifacts missing). "
                    "Re-collect with FDA granted."
                ),
            })
        elif fda["status"] in ("GRANTED", "LIKELY_GRANTED"):
            recs.append({
                "level": "OK",
                "message": f"FDA was granted ({fda['present']}/{fda['total']} protected artifacts present).",
            })

        if present >= 55:
            recs.append({"level": "OK", "message": f"Collection looks complete ({present}/{total} artifacts present)."})
        elif present >= 40:
            recs.append({"level": "WARN", "message": f"Collection partially complete ({present}/{total}). Check missing artifacts."})
        else:
            recs.append({"level": "CRITICAL", "message": f"Collection may be incomplete ({present}/{total}). Verify collector ran correctly."})

        wal_missing_names = [k for k, v in wal_results.items() if v["status"] == "WAL_MISSING"]
        wal_missing_real = [n for n in wal_missing_names if "TCC" not in n]
        wal_missing_tcc = [n for n in wal_missing_names if "TCC" in n]
        if wal_missing_real:
            recs.append({
                "level": "WARN",
                "message": f"{len(wal_missing_real)} database(s) missing WAL: {', '.join(wal_missing_real)}",
            })
        if wal_missing_tcc:
            recs.append({
                "level": "INFO",
                "message": "TCC database(s) missing WAL (normal, macOS checkpoints immediately).",
            })

        return recs

    def run(self) -> dict:
        """Run all checks and return a structured result dict."""
        self.discover_users()
        self.load_metadata()
        artifact_results = self.check_artifact_presence()
        wal_results = self.check_wal_completeness()
        fda = self.infer_fda_status(artifact_results)
        recs = self.generate_recommendations(artifact_results, wal_results, fda)

        return {
            "metadata": self.metadata,
            "users": self.users,
            "artifacts": artifact_results,
            "wal_completeness": wal_results,
            "fda_inference": fda,
            "recommendations": recs,
            "summary": {
                "total_artifacts": len(artifact_results),
                "present": sum(1 for v in artifact_results.values() if v["status"] == "PRESENT"),
                "missing": sum(1 for v in artifact_results.values() if v["status"] == "MISSING"),
                "wal_complete": sum(1 for v in wal_results.values() if v["status"] == "COMPLETE"),
                "wal_missing": sum(1 for v in wal_results.values() if v["status"] == "WAL_MISSING"),
                "fda_status": fda["status"],
            },
        }

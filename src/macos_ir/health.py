#!/usr/bin/env python3
"""Collection Health Report — validates a Velociraptor macOS collection.

Author: Ali Jammal

Checks artifact presence, SQLite WAL completeness, FDA/SIP inference,
and provides actionable recommendations.

Usage:
    python3 collection_health.py /path/to/extracted/collection
    python3 collection_health.py /path/to/extracted/collection -j
    python3 collection_health.py /path/to/extracted/collection -v
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Artifact registry: 70 YAML collectors → expected paths in uploads/auto/
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
    # ── New collectors (paired with the 2026 Dissect plugin set) ──
    "Photos": {
        "category": "User Activity",
        "privilege": "FDA",
        "paths": [
            "Users/*/Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
        ],
        "check": "per_user",
    },
    "AuthDB": {
        "category": "System",
        "privilege": "ROOT",
        "paths": ["private/var/db/auth.db"],
        "check": "exact",
    },
    "HomeKit": {
        "category": "Device State",
        "privilege": "USER",
        "paths": ["Users/*/Library/HomeKit/core.sqlite"],
        "check": "per_user",
    },
    "LinkPresentation": {
        "category": "User Activity",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/Daemon Containers/*/Data/database/linkd.metadatastore.sqlite3",
        ],
        "check": "any",
    },
    "BLEDevices": {
        "category": "Network",
        "privilege": "ROOT",
        "paths": ["Library/Bluetooth/com.apple.MobileBluetooth.ledevices.other.db"],
        "check": "exact",
    },
    "Shortcuts": {
        "category": "User Activity",
        "privilege": "USER",
        "paths": ["Users/*/Library/Shortcuts/ToolKit"],
        "check": "dir_any",
    },
    "Trial": {
        "category": "System",
        "privilege": "USER",
        "paths": ["Users/*/Library/Trial"],
        "check": "dir_any",
    },
    "IdentityServices": {
        "category": "Communications",
        "privilege": "USER",
        "paths": ["Users/*/Library/IdentityServices/ids-query.db"],
        "check": "per_user",
    },
    "StatusKit": {
        "category": "User Activity",
        "privilege": "USER",
        "paths": ["Users/*/Library/StatusKit/database/statuskit-cloud.db"],
        "check": "per_user",
    },
    "AppleMediaServices": {
        "category": "User Activity",
        "privilege": "USER",
        "paths": [
            "Users/*/Library/AppleMediaServices/Engagement/journeys/database/app.db",
            "Users/*/Library/AppleMediaServices/Engagement/analytics/database/app.db",
        ],
        "check": "any",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# SQLite WAL check: artifacts where we expect db + wal + shm
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
# FDA indicators: if these are present, FDA was likely granted
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

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colors
# ──────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls):
        for attr in ["RESET", "BOLD", "DIM", "GREEN", "YELLOW", "RED", "CYAN", "WHITE"]:
            setattr(cls, attr, "")


# ──────────────────────────────────────────────────────────────────────────────
# Main engine
# ──────────────────────────────────────────────────────────────────────────────

class CollectionHealth:
    def __init__(self, collection_dir):
        self.collection_dir = Path(collection_dir)
        self.uploads_auto = self.collection_dir / "uploads" / "auto"
        if not self.uploads_auto.is_dir():
            # Maybe they pointed directly at uploads/auto
            if self.collection_dir.name == "auto" and (self.collection_dir / "Users").is_dir():
                self.uploads_auto = self.collection_dir
                self.collection_dir = self.collection_dir.parent.parent
            elif (self.collection_dir / "auto").is_dir():
                self.uploads_auto = self.collection_dir / "auto"
                self.collection_dir = self.collection_dir.parent
            else:
                print(f"Error: Cannot find uploads/auto/ under {collection_dir}", file=sys.stderr)
                sys.exit(1)
        self.users = []
        self.metadata = {}

    def discover_users(self):
        users_dir = self.uploads_auto / "Users"
        if not users_dir.is_dir():
            return []
        self.users = sorted([
            d.name for d in users_dir.iterdir()
            if d.is_dir() and d.name not in ("Shared", ".localized", "%2Elocalized")
        ])
        return self.users

    def load_metadata(self):
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
                    result["os_version"] = f"{os_info.get('system', '')} {os_info.get('release', '')} ({os_info.get('machine', '')})"
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
                        # Velociraptor uses nanoseconds since epoch
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

        # Try to get OS version from SystemVersion.plist
        sv_path = self.uploads_auto / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
        if sv_path.exists():
            try:
                import plistlib
                with open(sv_path, "rb") as f:
                    sv = plistlib.load(f)
                result["os_version"] = f"{sv.get('ProductName', 'macOS')} {sv.get('ProductUserVisibleVersion', '')} ({sv.get('ProductBuildVersion', '')})"
            except Exception:
                pass

        self.metadata = result
        return result

    def _resolve_paths(self, pattern):
        """Resolve a path pattern against uploads/auto, handling Users/* substitution."""
        if "Users/*" in pattern or "Users/*/" in pattern:
            results = []
            for user in self.users:
                resolved = pattern.replace("Users/*", f"Users/{user}", 1)
                full = self.uploads_auto / resolved
                results.append(full)
            return results
        elif "*" in pattern:
            # Use glob for other wildcards
            try:
                return list(self.uploads_auto.glob(pattern))[:20]
            except Exception:
                return []
        else:
            return [self.uploads_auto / pattern]

    def _path_exists(self, p):
        return p.exists() or p.is_symlink()

    def _dir_has_files(self, d):
        if not d.is_dir():
            return False
        try:
            return any(True for _ in d.iterdir())
        except PermissionError:
            return False

    def check_artifact_presence(self):
        results = {}
        for name, spec in ARTIFACT_REGISTRY.items():
            check = spec.get("check", "any")
            paths = spec["paths"]
            found_count = 0
            checked = 0

            if check == "exact":
                for p in paths:
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._path_exists(rp):
                            found_count += 1

            elif check == "exact_or_alt":
                for p in paths + spec.get("alt_paths", []):
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._path_exists(rp):
                            found_count += 1

            elif check == "per_user":
                for p in paths:
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

            elif check in ("dir_any", "any_mixed"):
                for p in paths:
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._path_exists(rp) or self._dir_has_files(rp):
                            found_count += 1

            elif check == "any":
                for p in paths:
                    resolved = self._resolve_paths(p)
                    for rp in resolved:
                        checked += 1
                        if self._path_exists(rp):
                            found_count += 1

            elif check in ("screentime", "launchpad", "quicklook", "dsstore"):
                # Special checks for paths with deep wildcards
                checked = 1
                base = self.uploads_auto / paths[0]
                if check == "dsstore":
                    # Check if any .DS_Store or %2EDS_Store exists under Users/
                    base = self.uploads_auto / "Users"
                    if base.is_dir():
                        for ds in base.rglob("*DS_Store"):
                            found_count = 1
                            break
                elif base.is_dir():
                    # Walk looking for the target
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
                            # Don't walk too deep
                            depth = root.replace(str(base), "").count(os.sep)
                            if depth > 5:
                                dirs.clear()
                    except Exception:
                        pass

            if found_count > 0:
                status = "PRESENT"
            else:
                status = "MISSING"

            results[name] = {
                "status": status,
                "found": found_count,
                "checked": checked,
                "category": spec["category"],
                "privilege": spec["privilege"],
            }

        return results

    def check_wal_completeness(self):
        results = {}
        for label, db_pattern in SQLITE_WAL_ARTIFACTS.items():
            resolved = self._resolve_paths(db_pattern)
            wal_pattern = db_pattern + "-wal"
            shm_pattern = db_pattern + "-shm"
            wal_resolved = self._resolve_paths(wal_pattern)
            shm_resolved = self._resolve_paths(shm_pattern)

            for i, db_path in enumerate(resolved):
                wal_path = wal_resolved[i] if i < len(wal_resolved) else None
                shm_path = shm_resolved[i] if i < len(shm_resolved) else None

                db_exists = self._path_exists(db_path) if db_path else False
                wal_exists = self._path_exists(wal_path) if wal_path else False
                shm_exists = self._path_exists(shm_path) if shm_path else False

                if not db_exists:
                    continue  # Skip non-existent databases

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

                # Check WAL size — if WAL is 0 bytes that's also noteworthy
                wal_size = 0
                db_size = 0
                try:
                    if db_exists:
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

    def infer_fda_status(self, artifact_results):
        present = 0
        missing = 0
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

    def check_sip_blocked(self):
        results = {}
        for name in SIP_BLOCKED:
            spec = ARTIFACT_REGISTRY.get(name, {})
            for p in spec.get("paths", []):
                resolved = self._resolve_paths(p)
                for rp in resolved:
                    exists = self._path_exists(rp) or self._dir_has_files(rp)
                    results[name] = "PRESENT" if exists else "MISSING (expected on live)"

        # SystemKey specifically
        sk = self.uploads_auto / "private" / "var" / "db" / "SystemKey"
        results["KeyChain (SystemKey)"] = "PRESENT" if sk.exists() else "MISSING (expected on live)"
        return results

    def generate_recommendations(self, artifact_results, wal_results, fda):
        recs = []
        present = sum(1 for v in artifact_results.values() if v["status"] == "PRESENT")
        missing = sum(1 for v in artifact_results.values() if v["status"] == "MISSING")
        total = len(artifact_results)

        # FDA recommendation
        if fda["status"] in ("NOT_GRANTED", "LIKELY_NOT_GRANTED"):
            recs.append({
                "level": "CRITICAL",
                "message": f"FDA likely NOT granted — {fda['missing']}/{fda['total']} protected artifacts missing. "
                           "Re-collect with FDA granted to the collector binary.",
            })
        elif fda["status"] in ("GRANTED", "LIKELY_GRANTED"):
            recs.append({
                "level": "OK",
                "message": f"FDA was granted — {fda['present']}/{fda['total']} protected artifacts present.",
            })

        # Overall completeness
        if present >= 55:
            recs.append({"level": "OK", "message": f"Collection looks complete ({present}/{total} artifacts present)."})
        elif present >= 40:
            recs.append({"level": "WARN", "message": f"Collection partially complete ({present}/{total} artifacts present). Check missing artifacts."})
        else:
            recs.append({"level": "CRITICAL", "message": f"Collection may be incomplete ({present}/{total} artifacts present). Verify collector ran correctly."})

        # WAL warnings
        wal_missing = sum(1 for v in wal_results.values() if v["status"] == "WAL_MISSING")
        if wal_missing > 0:
            recs.append({
                "level": "WARN",
                "message": f"{wal_missing} SQLite database(s) missing WAL files — recent uncommitted writes may be truncated.",
            })

        # SIP note
        sip_missing = sum(1 for v in artifact_results.values()
                         if v["privilege"] == "SIP" and v["status"] == "MISSING")
        if sip_missing > 0:
            recs.append({
                "level": "INFO",
                "message": f"{sip_missing} SIP-blocked artifact(s) missing — expected on live SIP-enabled systems.",
            })

        return recs

    def run(self):
        self.discover_users()
        self.load_metadata()
        artifact_results = self.check_artifact_presence()
        wal_results = self.check_wal_completeness()
        fda = self.infer_fda_status(artifact_results)
        sip = self.check_sip_blocked()
        recs = self.generate_recommendations(artifact_results, wal_results, fda)

        return {
            "metadata": self.metadata,
            "users": self.users,
            "artifacts": artifact_results,
            "wal_completeness": wal_results,
            "fda_inference": fda,
            "sip_blocked": sip,
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


# ──────────────────────────────────────────────────────────────────────────────
# Terminal output
# ──────────────────────────────────────────────────────────────────────────────

def format_terminal(result, verbose=False):
    meta = result["metadata"]
    summary = result["summary"]
    artifacts = result["artifacts"]
    wal = result["wal_completeness"]
    fda = result["fda_inference"]
    sip = result["sip_blocked"]
    recs = result["recommendations"]

    line = "=" * 72
    print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  COLLECTION HEALTH REPORT{C.RESET}")
    print(f"{C.DIM}  Author: Ali Jammal{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}")

    # Metadata
    print(f"\n{C.BOLD}COLLECTION METADATA{C.RESET}")
    print(f"  Hostname:        {C.CYAN}{meta['hostname']}{C.RESET}")
    print(f"  OS Version:      {meta['os_version']}")
    print(f"  Collection Date: {meta['collection_date']}")
    if meta["duration_seconds"]:
        mins = int(meta["duration_seconds"]) // 60
        secs = int(meta["duration_seconds"]) % 60
        print(f"  Duration:        {mins}m {secs}s")
    print(f"  Total Files:     {meta['total_files']:,}")
    if meta["total_bytes"]:
        gb = meta["total_bytes"] / (1024 ** 3)
        print(f"  Total Size:      {gb:.1f} GB")
    print(f"  Users Found:     {', '.join(result['users']) or 'none'}")

    # Artifact presence
    print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"{C.BOLD}ARTIFACT PRESENCE ({summary['total_artifacts']} artifacts){C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"\n  {C.GREEN}PRESENT: {summary['present']}{C.RESET}   "
          f"{C.RED}MISSING: {summary['missing']}{C.RESET}")

    # Group by category
    categories = {}
    for name, info in artifacts.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((name, info))

    for cat in sorted(categories.keys()):
        print(f"\n  {C.BOLD}{C.DIM}── {cat} ──{C.RESET}")
        for name, info in sorted(categories[cat], key=lambda x: (x[1]["status"] != "PRESENT", x[0])):
            if info["status"] == "PRESENT":
                icon = f"{C.GREEN}PRESENT{C.RESET}"
            else:
                icon = f"{C.RED}MISSING{C.RESET}"
            priv = f"{C.DIM}[{info['privilege']}]{C.RESET}"
            print(f"    [{icon}]  {name:<30} {priv}")

    # WAL completeness
    if wal:
        print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
        print(f"{C.BOLD}SQLITE WAL COMPLETENESS ({len(wal)} databases found){C.RESET}")
        print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}")

        complete = sum(1 for v in wal.values() if v["status"] == "COMPLETE")
        wal_miss = sum(1 for v in wal.values() if v["status"] == "WAL_MISSING")
        print(f"\n  {C.GREEN}COMPLETE: {complete}{C.RESET}   "
              f"{C.YELLOW}WAL_MISSING: {wal_miss}{C.RESET}")

        for label, info in sorted(wal.items()):
            if info["status"] == "COMPLETE":
                icon = f"{C.GREEN}COMPLETE{C.RESET}"
            elif info["status"] == "WAL_MISSING":
                icon = f"{C.YELLOW}WAL_MISSING{C.RESET}"
            else:
                icon = f"{C.DIM}{info['status']}{C.RESET}"

            size_info = ""
            if verbose:
                db_kb = info["db_size"] // 1024
                wal_kb = info["wal_size"] // 1024
                size_info = f" (db: {db_kb}KB, wal: {wal_kb}KB)"

            print(f"    [{icon}]  {label}{size_info}")

    # FDA inference
    print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"{C.BOLD}FULL DISK ACCESS INFERENCE{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}")

    if fda["status"] in ("GRANTED", "LIKELY_GRANTED"):
        status_color = C.GREEN
    elif fda["status"] in ("NOT_GRANTED", "LIKELY_NOT_GRANTED"):
        status_color = C.RED
    else:
        status_color = C.YELLOW

    print(f"\n  FDA Status:  {status_color}{C.BOLD}{fda['status']}{C.RESET} ({fda['confidence']} confidence)")
    print(f"  Protected artifacts present: {fda['present']}/{fda['total']}")
    print()
    for name, present in fda["indicators"].items():
        if present:
            print(f"    {C.GREEN}[YES]{C.RESET}  {name}")
        else:
            print(f"    {C.RED}[ NO]{C.RESET}  {name}")

    # SIP
    print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"{C.BOLD}SIP-BLOCKED ARTIFACTS{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}")
    for name, status in sip.items():
        print(f"\n    {name}: {C.DIM}{status}{C.RESET}")

    # Recommendations
    print(f"\n{C.BOLD}{C.WHITE}{line}{C.RESET}")
    print(f"{C.BOLD}RECOMMENDATIONS{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{line}{C.RESET}\n")
    for rec in recs:
        level = rec["level"]
        if level == "OK":
            icon = f"{C.GREEN}[OK]{C.RESET}"
        elif level == "WARN":
            icon = f"{C.YELLOW}[WARN]{C.RESET}"
        elif level == "CRITICAL":
            icon = f"{C.RED}[CRITICAL]{C.RESET}"
        else:
            icon = f"{C.CYAN}[INFO]{C.RESET}"
        print(f"  {icon}  {rec['message']}")

    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MacOS Velociraptor Collection Health Report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 collection_health.py ~/dissect-collections/2026-04-12/
  python3 collection_health.py ~/dissect-collections/2026-04-12/ -j
  python3 collection_health.py ~/dissect-collections/2026-04-12/ -v
  python3 collection_health.py ~/dissect-collections/2026-04-12/uploads/auto
""",
    )
    parser.add_argument("collection_dir", help="Path to extracted collection (parent of uploads/auto/)")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show file sizes and details")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    health = CollectionHealth(args.collection_dir)
    result = health.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        format_terminal(result, verbose=args.verbose)


if __name__ == "__main__":
    main()

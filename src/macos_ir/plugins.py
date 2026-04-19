"""Plugin registry — every known macOS dissect plugin function, grouped by category."""

from __future__ import annotations

PLUGIN_FUNCTIONS: dict[str, list[str]] = {
    "web": [
        "safari.history", "safari.downloads", "safari.bookmarks",
        "chromium.history", "chromium.downloads", "chromium.searches",
        "chromium.bookmarks", "chromium.cookies", "chromium.logins",
        "firefox.history", "firefox.downloads", "firefox.searches", "firefox.bookmarks",
        "firefox.cookies", "firefox.logins", "firefox.formhistory",
        "cookies.entries",
    ],
    "execution": [
        "knowledgec.app_usage", "knowledgec.web_usage", "knowledgec.media_usage",
        "knowledgec.notifications", "knowledgec.intents", "knowledgec.display",
        "biome.app_in_focus", "biome.app_intents",
        "biome.now_playing", "biome.web_usage", "biome.app_activity", "biome.media_usage",
        "biome.wifi_connections", "biome.bluetooth", "biome.wifi", "biome.display",
        "biome.location", "biome.notifications",
        "biome.safari_navigations", "biome.safari_page_load", "biome.safari_history",
        "biome.user_focus", "biome.third_party_apps",
        "biome.safari_pageview",
        "biome.siri_execution", "biome.messages_read",
        "biome.carplay", "biome.screen_sharing",
        "screentime.usage", "screentime.blocks",
        "spotlightshortcuts.entries", "spotlight.applist",
        "launchpad.apps",
        "interactions.entries", "interactions.contacts",
    ],
    "communication": [
        "imessage.messages", "imessage.chats", "imessage.attachments",
        "callhistory.calls",
        "facetime.links", "facetime.handles",
        "addressbook.contacts", "addressbook.emails", "addressbook.phones",
        "notifications.entries",
        "notes.entries", "notes.attachments",
    ],
    "persistence": [
        "autostart.launch_agents", "autostart.launch_daemons", "autostart.launch_items",
        "autostart.system_extensions", "autostart.kernel_extensions", "autostart.cronjobs",
        "autostart.periodic", "autostart.startup_items", "autostart.startup_files",
        "kext.installed", "kext.load_history", "kext.system_extensions",
        "execpolicy.entries",
        "applications.installed",
    ],
    "security": [
        "tcc.access", "tcc.expired", "tcc.location_clients",
        "firewall.pf_rules", "firewall.alf_config", "firewall.alf_exceptions",
        "firewall.alf_services", "firewall.alf_apps",
        "keychain.generic", "keychain.internet", "keychain.certificates",
        "profiles.installed", "profiles.payloads", "profiles.settings",
    ],
    "system": [
        "preferences.entries",
        "osinfo.version", "osinfo.install_date",
        "localusers.entries",
        "localtime.info",
        "hostfile.entries",
        "etcfiles.entries",
        "sudoers.entries",
        "sharepoints.entries",
        "dhcp.leases",
        "logs.system", "logs.install",
        "logs.asl", "logs.asl_system", "logs.asl_powermanagement", "logs.asl_diagnostics",
        "logs.audit_events",
        "crashreporter.entries", "crashreporter.events",
        "powerlogs.sleep_wake", "powerlogs.app_usage", "powerlogs.network",
    ],
    "filesystem": [
        "fsevents.events",
        "dsstore.files", "dsstore.entries",
        "docrevisions.generations", "docrevisions.files",
        "trash.files", "trash.icloud",
        "quicklook.thumbnails",
    ],
    "network": [
        "wifiintelligence.wifi_events", "wifiintelligence.person_interactions",
        "wifiintelligence.entity_aliases",
        "ssh.known_hosts", "ssh.config",
        "ard.config", "ard.access",
        "msrdc.connections",
        "screensharing.connections",
    ],
    "auth": [
        "utmpx.entries",
        "sudolog.entries",
        "shellhistory.entries",
    ],
    "installation": [
        "wallet.passes", "wallet.pass_details", "wallet.transactions",
        "wallet.payment_cards",
        "officemru.entries",
        "printjobs.entries",
        "installhistory.entries",
        "softwareupdate.appstore_installs", "softwareupdate.appstore_updates",
        "softwareupdate.receipts",
    ],
    "accounts": [
        "accounts.entries", "accounts.properties", "accounts.credentials",
        "icloudfiles.files",
    ],
    "devicestate": [
        "savedstate.entries",
        "terminalstate.files",
        "sharedfilelist.favorites", "sharedfilelist.volumes",
        "sharedfilelist.recent_apps", "sharedfilelist.recent_docs", "sharedfilelist.projects",
        "idevicebackup.info", "idevicebackup.files",
    ],
}

# Plugins that take minutes each or produce huge data; off by default.
SLOW_FUNCTIONS: set[str] = {"logs.system", "logs.install", "fsevents.events"}


def build_func_category_map() -> dict[str, str]:
    """Flatten PLUGIN_FUNCTIONS into {func_name: category}."""
    out: dict[str, str] = {}
    for cat, funcs in PLUGIN_FUNCTIONS.items():
        for f in funcs:
            out.setdefault(f, cat)
    return out


FUNC_CATEGORY = build_func_category_map()


def get_selected_functions(
    *,
    category_filter: set[str] | None = None,
    source_filter: set[str] | None = None,
    include_slow: bool = False,
) -> list[tuple[str, str]]:
    """Return [(func_name, category)] in stable order, applying filters."""
    selected = []
    for func in sorted(FUNC_CATEGORY, key=lambda f: (FUNC_CATEGORY[f], f)):
        category = FUNC_CATEGORY[func]
        if source_filter and func not in source_filter:
            continue
        if category_filter and category not in category_filter:
            continue
        if func in SLOW_FUNCTIONS and not include_slow:
            continue
        selected.append((func, category))
    return selected

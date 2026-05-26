#!/bin/zsh
# macOS forensic collector — shell-script equivalent of MacOS.Collection.* Velociraptor artifacts.
# Produces a Dissect-friendly filesystem-mirror layout:
#
#   collection-<host>-<ts>/
#     filesystem/<absolute source path>...    # Dissect dir loader points here
#     manifest.csv                             # artifact,source,dest,size,sha256,status
#     collection.log                           # per-artifact begin/end + errors
#     ARTIFACTS.txt                            # summary: artifact -> count of items copied
#
# Usage: sudo ./collect_macos.sh [--fast] [--no-hash] [output_dir]
#   --fast     : batch-copy whole directories when glob ends in **/*  (big speedup)
#   --no-hash  : skip per-file sha256 (hash the final tarball only)   (big speedup)
# Full Disk Access strongly recommended (System Settings > Privacy > Full Disk Access > Terminal).

setopt extended_glob null_glob no_nomatch pipefail
umask 077

FAST=1          # default on — batch recursive dirs
NO_HASH=1       # default on — hash tarball only; pass --hash to force per-file
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --fast)    FAST=1 ;;
    --slow)    FAST=0 ;;
    --no-hash) NO_HASH=1 ;;
    --hash)    NO_HASH=0 ;;
    *) print "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

HOST=$(hostname -s)
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTROOT="${1:-/tmp/collection-${HOST}-${TS}}"
FS="${OUTROOT}/filesystem"
MANIFEST="${OUTROOT}/manifest.csv"
LOG="${OUTROOT}/collection.log"
SUMMARY="${OUTROOT}/ARTIFACTS.txt"

mkdir -p "$FS" || { print "cannot create $FS" >&2; exit 1; }
: > "$LOG"
: > "$SUMMARY"
print "artifact,source,dest,size,sha256,status" > "$MANIFEST"

CURRENT_ARTIFACT=""
CURRENT_COUNT=0
CURRENT_FAIL=0

log()  { print -r -- "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }
logq() { print -r -- "[$(date -u +%FT%TZ)] $*" >> "$LOG"; }

copy_one() {
  local src="$1"
  [[ -e "$src" || -L "$src" ]] || return 0
  local dest="${FS}${src}"
  mkdir -p "${dest:h}" 2>/dev/null
  if ditto --noqtn "$src" "$dest" 2>>"$LOG"; then
    local size="" sha=""
    if [[ -f "$dest" && ! -L "$dest" ]]; then
      size=$(stat -f %z "$dest" 2>/dev/null)
      if (( NO_HASH == 0 )); then
        sha=$(shasum -a 256 "$dest" 2>/dev/null | awk '{print $1}')
      else
        sha="-"
      fi
    elif [[ -d "$dest" ]]; then
      sha="DIR"
    elif [[ -L "$dest" ]]; then
      sha="SYMLINK"
    fi
    print -r -- "${CURRENT_ARTIFACT},\"${src}\",\"${dest}\",${size},${sha},ok" >> "$MANIFEST"
    (( CURRENT_COUNT += 1 ))
  else
    print -r -- "${CURRENT_ARTIFACT},\"${src}\",\"${dest}\",,,fail" >> "$MANIFEST"
    (( CURRENT_FAIL += 1 ))
  fi
}

# Batch-copy a whole directory tree with a single ditto fork.
copy_tree() {
  local src="$1"
  [[ -d "$src" ]] || return 0
  local dest="${FS}${src}"
  mkdir -p "${dest:h}" 2>/dev/null
  if ditto --noqtn "$src" "$dest" 2>>"$LOG"; then
    local n
    n=$(find "$dest" -type f 2>/dev/null | wc -l | tr -d ' ')
    print -r -- "${CURRENT_ARTIFACT},\"${src}/**\",\"${dest}\",,TREE,ok" >> "$MANIFEST"
    (( CURRENT_COUNT += n ))
  else
    print -r -- "${CURRENT_ARTIFACT},\"${src}/**\",\"${dest}\",,,fail" >> "$MANIFEST"
    (( CURRENT_FAIL += 1 ))
  fi
}

art_begin() {
  CURRENT_ARTIFACT="$1"; CURRENT_COUNT=0; CURRENT_FAIL=0
  log "BEGIN ${CURRENT_ARTIFACT}"
}

art_end() {
  log "END   ${CURRENT_ARTIFACT} (items=${CURRENT_COUNT} fail=${CURRENT_FAIL})"
  printf "%-32s items=%-6d fail=%d\n" "$CURRENT_ARTIFACT" "$CURRENT_COUNT" "$CURRENT_FAIL" >> "$SUMMARY"
}

# collect <ArtifactName> <glob1> [glob2 ...]
# Globs use zsh extended_glob; ** recurses. Patterns are expanded at call time.
collect() {
  local art="$1"; shift
  art_begin "$art"
  local g f root
  for g in "$@"; do
    # Fast path: glob ending in /**/* → strip it and copy the parent dir(s) whole.
    if (( FAST )) && [[ "$g" == *'/**/*' ]]; then
      root="${g%/\*\*/\*}"
      for f in ${~root}; do
        [[ -d "$f" ]] && copy_tree "$f" || copy_one "$f"
      done
    else
      for f in ${~g}; do
        copy_one "$f"
      done
    fi
  done
  art_end
}

# ---- FDA smoke test -------------------------------------------------------
log "macOS collector starting — host=${HOST} out=${OUTROOT}"
log "kernel=$(uname -a)"
if [[ $EUID -ne 0 ]]; then
  log "WARN: not running as root; many system-owned artifacts will be skipped"
fi
FIRST_USER_HOME=$(print -r -- /Users/*(/N) | awk '{print $1}')
if [[ -n "$FIRST_USER_HOME" && ! -r "${FIRST_USER_HOME}/Library/Mail" ]]; then
  if [[ -d "${FIRST_USER_HOME}/Library/Mail" ]]; then
    log "WARN: ~/Library/Mail exists but is unreadable — Terminal likely lacks Full Disk Access. FDA-gated artifacts will be empty."
  fi
fi

# ---- Artifacts (71) -------------------------------------------------------
# Order roughly matches original Velociraptor collector. FDA-gated artifacts marked.

collect AddressBook \
  '/Users/*/Library/Application Support/AddressBook/**/*'                                # FDA

collect AlternateLog \
  '/private/var/log/**/*' \
  '/Users/*/Library/Logs/**/*' \
  '/etc/security/**/*'

collect AppleMail \
  '/Users/*/Library/Mail/**/*'                                                           # FDA

collect AppleNotes \
  '/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite' \
  '/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-wal' \
  '/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-shm'         # FDA

collect ApplePayWallet \
  '/Users/*/Library/Passes/passes23.sqlite' \
  '/Users/*/Library/Passes/passes23.sqlite-wal' \
  '/Users/*/Library/Passes/passes23.sqlite-shm'                                          # FDA

collect Applications \
  '/Users/*/Applications/*/Contents/Info.plist' \
  '/Applications/*/Contents/Info.plist'

collect Applist \
  '/Users/*/Library/Application Support/com.apple.spotlight/appList.dat'

collect Autostart \
  '/System/Library/Extensions/**/*' \
  '/Library/Extensions/**/*' \
  '/System/Library/LaunchDaemons/**/*' \
  '/Library/LaunchDaemons/**/*' \
  '/System/Library/LaunchAgents/**/*' \
  '/Library/LaunchAgents/**/*' \
  '/Users/*/Library/LaunchAgents/**/*' \
  '/System/Library/StartupItems/**/*' \
  '/Library/StartupItems/**/*' \
  '/private/etc/periodic/daily/**/*' \
  '/private/etc/periodic/monthly/**/*' \
  '/private/etc/periodic/weekly/**/*' \
  '/private/etc/launchd.conf' \
  '/private/etc/rc.common'

collect Biomes \
  '/Users/*/Library/Biome/**/*' \
  '/private/var/db/biome/**/*'

collect Calendars \
  '/Users/*/Library/Calendars/**/*'                                                      # FDA

collect CallHistory \
  '/Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata' \
  '/Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata-wal' \
  '/Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata-shm'         # FDA

collect ChromiumBrowsers \
  '/Users/*/Library/Application Support/Google/Chrome/(Default|Profile*|Guest Profile)/(History|History-journal|History-wal|Cookies|Cookies-journal|Cookies-wal|Bookmarks|Bookmarks.bak|Login Data|Login Data-journal|Login Data For Account|Login Data For Account-journal|Web Data|Web Data-journal|Shortcuts|Shortcuts-journal|Top Sites|Top Sites-journal|Favicons|Favicons-journal|Preferences|Secure Preferences|Visited Links|Network Action Predictor|Network Action Predictor-journal)' \
  '/Users/*/Library/Application Support/Google/Chrome/(Local State|First Run)' \
  '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser(|-Beta|-Nightly)/(Default|Profile*|Guest Profile)/(History|History-journal|History-wal|Cookies|Cookies-journal|Cookies-wal|Bookmarks|Bookmarks.bak|Login Data|Login Data-journal|Login Data For Account|Login Data For Account-journal|Web Data|Web Data-journal|Shortcuts|Shortcuts-journal|Top Sites|Top Sites-journal|Favicons|Favicons-journal|Preferences|Secure Preferences|Visited Links|Network Action Predictor|Network Action Predictor-journal)' \
  '/Users/*/Library/Application Support/BraveSoftware/Brave-Browser(|-Beta|-Nightly)/(Local State|First Run)' \
  '/Users/*/Library/Application Support/Microsoft Edge(| Beta| Dev)/(Default|Profile*|Guest Profile)/(History|History-journal|History-wal|Cookies|Cookies-journal|Cookies-wal|Bookmarks|Bookmarks.bak|Login Data|Login Data-journal|Login Data For Account|Login Data For Account-journal|Web Data|Web Data-journal|Shortcuts|Shortcuts-journal|Top Sites|Top Sites-journal|Favicons|Favicons-journal|Preferences|Secure Preferences|Visited Links|Network Action Predictor|Network Action Predictor-journal)' \
  '/Users/*/Library/Application Support/Microsoft Edge(| Beta| Dev)/(Local State|First Run)' \
  '/Users/*/Library/Application Support/Chromium/(Default|Profile*|Guest Profile)/(History|History-journal|History-wal|Cookies|Cookies-journal|Cookies-wal|Bookmarks|Bookmarks.bak|Login Data|Login Data-journal|Web Data|Web Data-journal|Preferences|Secure Preferences|Visited Links)' \
  '/Users/*/Library/Application Support/Chromium/(Local State|First Run)' \
  '/Users/*/Library/Application Support/com.operasoftware.Opera(|GX)/(History|History-journal|Cookies|Cookies-journal|Bookmarks|Login Data|Login Data-journal|Web Data|Web Data-journal|Preferences|Visited Links)' \
  '/Users/*/Library/Application Support/com.operasoftware.Opera(|GX)/(Local State|First Run)' \
  '/Users/*/Library/Application Support/Vivaldi/(Default|Profile*|Guest Profile)/(History|History-journal|Cookies|Cookies-journal|Bookmarks|Login Data|Web Data|Preferences|Visited Links)' \
  '/Users/*/Library/Application Support/Vivaldi/(Local State|First Run)'                 # FDA

collect CrashReporter \
  '/Users/*/Library/Application Support/CrashReporter/*.plist'

collect DHCPLease \
  '/private/var/db/dhcpclient/leases/**/*'

collect DSStore \
  '/Users/**/.DS_Store' \
  '/Applications/**/.DS_Store' \
  '/Library/**/.DS_Store'

collect DocumentRevisions \
  '/System/Volumes/Data/.DocumentRevisions-V100/**/*' \
  '/.DocumentRevisions-V100/**/*'

collect FaceTime \
  '/Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3' \
  '/Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3-wal' \
  '/Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3-shm'                   # FDA

collect FavoriteVolumes \
  '/Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl3'

collect FindMy \
  '/Users/*/Library/Caches/com.apple.findmy.fmipcore/Items.data' \
  '/Users/*/Library/Caches/com.apple.findmy.fmfcore/FriendCacheData.data'

collect FirefoxFiles \
  '/Users/*/Library/Application Support/Firefox/Profiles/**/*'                           # FDA

collect FirewallConfiguration \
  '/etc/pf.conf' \
  '/private/etc/pf.conf' \
  '/etc/pf.anchors/**/*' \
  '/private/etc/pf.anchors/**/*' \
  '/usr/libexec/ApplicationFirewall/com.apple.alf.plist' \
  '/Library/Preferences/com.apple.alf.plist'

collect FsEvents \
  '/.fseventsd/**/*' \
  '/System/Volumes/Data/.fseventsd/**/*' \
  '/private/var/db/fseventsd/**/*'

collect InstallHistory \
  '/Library/Receipts/InstallHistory.plist'

collect Interactions \
  '/private/var/db/CoreDuet/People/interactionC.db' \
  '/private/var/db/CoreDuet/People/interactionC.db-wal' \
  '/private/var/db/CoreDuet/People/interactionC.db-shm'

collect InternetAccounts \
  '/Users/*/Library/Accounts/**/*'

collect KernelExtensions \
  '/private/var/db/loadedkextmt.plist' \
  '/private/var/db/SystemPolicyConfiguration/KextPolicy' \
  '/private/var/db/SystemPolicyConfiguration/ExecPolicy' \
  '/Library/Apple/System/Library/Extensions/**/*' \
  '/System/Library/Extensions/**/*' \
  '/Library/Extensions/**/*' \
  '/Library/StagedExtensions/**/*' \
  '/Library/SystemExtensions/**/*'

collect KeyChain \
  '/Users/*/Library/Keychains/**/*' \
  '/private/var/db/SystemKey' \
  '/Library/Keychains/System.keychain'                                                   # FDA

collect KeyboardDictionary \
  '/Users/*/Library/Spelling/**/*'

collect KnowledgeC \
  '/private/var/db/CoreDuet/Knowledge/knowledgeC.db' \
  '/private/var/db/CoreDuet/Knowledge/knowledgeC.db-wal' \
  '/private/var/db/CoreDuet/Knowledge/knowledgeC.db-shm' \
  '/Users/*/Library/Application Support/Knowledge/knowledgeC.db' \
  '/Users/*/Library/Application Support/Knowledge/knowledgeC.db-wal' \
  '/Users/*/Library/Application Support/Knowledge/knowledgeC.db-shm'

collect LaunchPad \
  '/private/var/folders/*/*/0/com.apple.dock.launchpad/db/**/*' \
  '/Users/*/Library/Application Support/com.apple.dock.launchpad/db/**/*'

collect LibraryPreferences \
  '/Users/*/Library/Preferences/**/*' \
  '/Library/Preferences/**/*'

collect ManagedDeviceProfile \
  '/private/var/db/ConfigurationProfiles/**/*'

collect MicrosoftOfficeMRU \
  '/Users/*/Library/Containers/*/Data/Library/Preferences/*.securebookmarks.plist' \
  '/Users/*/Library/Containers/com.microsoft.*/Data/Library/Application Support/Microsoft/Office/*/spotlightindexer/AggregatedMRUSpotlightIndexedData.json'

collect Notifications \
  '/Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db' \
  '/Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db-wal' \
  '/Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db-shm' \
  '/private/var/folders/*/*/*/com.apple.notificationcenter/db2/db' \
  '/private/var/folders/*/*/*/com.apple.notificationcenter/db2/db-wal' \
  '/private/var/folders/*/*/*/com.apple.notificationcenter/db2/db-shm'

collect OSInstallationDate \
  '/private/var/db/.AppleSetupDone' \
  '/private/var/db/softwareupdate/journal.plist'

collect OSName \
  '/System/Library/CoreServices/SystemVersion.plist' \
  '/System/Library/Kernels/kernel' \
  '/mach_kernel'

collect Powerlogs \
  '/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL' \
  '/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL-wal' \
  '/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL-shm'

collect PrintJobs \
  '/private/var/spool/cups/**/*' \
  '/etc/cups/ppd/*.ppd'

collect QuickLook \
  '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite' \
  '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite-wal' \
  '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite-shm' \
  '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/thumbnails.data'

collect Reminders \
  '/Users/*/Library/Group Containers/group.com.apple.reminders/Container_v1/Stores/**/*' # FDA

collect SafariFiles \
  '/Users/*/Library/Safari/**/*' \
  '/Users/*/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/TabSnapshots/**/*' \
  '/Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies' # FDA

collect SavedState \
  '/Users/*/Library/Saved Application State/**/*' \
  '/Users/*/Library/Daemon Containers/*/Data/Library/Saved Application State/**/*'

collect ScreenSharing \
  '/Users/*/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist' \
  '/private/var/db/com.apple.xpc.launchd/**/*'

collect ScreenTime \
  '/private/var/folders/*/*/0/com.apple.ScreenTimeAgent/**/*'

collect SharedFolder \
  '/private/var/db/dslocal/nodes/Default/sharepoints/**/*' \
  '/private/var/db/com.apple.xpc.launchd/**/*' \
  '/Library/Preferences/com.apple.RemoteManagement.plist'

collect ShellHistoryAndSessions \
  '/Users/*/.bash_history' \
  '/Users/*/.zsh_history' \
  '/Users/*/.history' \
  '/root/.bash_history' \
  '/root/.zsh_history' \
  '/Users/*/.bash_sessions/**/*' \
  '/Users/*/.zsh_sessions/**/*'

collect SoftwareInstallationUpdates \
  '/Users/*/Library/Caches/com.apple.appstoreagent/storeSystem.db' \
  '/Users/*/Library/Caches/com.apple.appstoreagent/storeSystem.db-wal' \
  '/Users/*/Library/Caches/com.apple.appstoreagent/storeSystem.db-shm' \
  '/Library/Receipts/InstallHistory.plist' \
  '/var/db/receipts/**/*' \
  '/Library/Preferences/com.apple.SoftwareUpdate.plist'

collect SpotlightShortCuts \
  '/Users/*/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts' \
  '/Users/*/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.v3' \
  '/Users/*/Library/Group Containers/group.com.apple.spotlight/com.apple.spotlight.Shortcuts.v3' \
  '/Users/*/Library/Metadata/CoreSpotlight/index.spotlightV3/**/*'

collect SSHHost \
  '/Users/*/.ssh/known_hosts' \
  '/Users/*/.ssh/authorized_keys'

collect Sudoers \
  '/etc/sudoers'

collect TCC \
  '/Library/Application Support/com.apple.TCC/TCC.db' \
  '/Library/Application Support/com.apple.TCC/TCC.db-wal' \
  '/Library/Application Support/com.apple.TCC/TCC.db-shm' \
  '/Users/*/Library/Application Support/com.apple.TCC/TCC.db' \
  '/Users/*/Library/Application Support/com.apple.TCC/TCC.db-wal' \
  '/Users/*/Library/Application Support/com.apple.TCC/TCC.db-shm' \
  '/private/var/db/locationd/clients.plist'                                              # FDA

collect TerminalState \
  '/Users/*/Library/Saved Application State/com.apple.Terminal.savedState/**/*' \
  '/Users/*/Library/Daemon Containers/*/Data/Library/Saved Application State/com.apple.Terminal.savedState/**/*'

collect Trash \
  '/Users/*/.Trash/**/*' \
  '/Users/*/Library/Mobile Documents/.Trash/**/*'                                        # FDA

collect Users \
  '/private/var/db/dslocal/nodes/Default/users/**/*' \
  '/private/var/db/dslocal/nodes/Default/groups/**/*'

collect WifiIntelligence \
  '/Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db' \
  '/Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db-wal' \
  '/Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db-shm'

collect ard \
  '/private/var/db/RemoteManagement/caches/AppUsage.tmp' \
  '/private/var/db/RemoteManagement/caches/AppUsage.plist' \
  '/private/var/db/RemoteManagement/caches/UserAcct.tmp'

collect cookies \
  '/Users/*/Library/Cookies/**/*' \
  '/Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/**/*'               # FDA

collect etcFolder \
  '/private/etc/**/*'

collect hosts \
  '/etc/hosts'

collect iCloud \
  '/Users/*/Library/Application Support/CloudDocs/session/db/server.db' \
  '/Users/*/Library/Application Support/CloudDocs/session/db/server.db-wal' \
  '/Users/*/Library/Application Support/CloudDocs/session/db/server.db-shm' \
  '/Users/*/Library/Application Support/CloudDocs/session/db/client.db' \
  '/Users/*/Library/Application Support/CloudDocs/session/db/client.db-wal' \
  '/Users/*/Library/Application Support/CloudDocs/session/db/client.db-shm' \
  '/Users/*/Library/SyncedPreferences/**/*' \
  '/Users/*/Library/Containers/*/Data/Library/SyncedPreferences/**/*' \
  '/Users/*/Library/Application Support/iCloud/Accounts/**/*'

collect iCloudLocalStorage \
  '/Users/*/Library/Mobile Documents/**/*'                                               # FDA

collect iDeviceBackup \
  '/Users/*/Library/Application Support/MobileSync/Backup/**/*'

collect iMessage \
  '/Users/*/Library/Messages/chat.db' \
  '/Users/*/Library/Messages/chat.db-wal' \
  '/Users/*/Library/Messages/chat.db-shm' \
  '/Users/*/Library/Messages/Attachments/**/*'                                           # FDA

collect localtime \
  '/etc/localtime'

collect lockdown \
  '/private/var/db/lockdown/**/*'

collect msrdc \
  '/Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite' \
  '/Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite-wal' \
  '/Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite-shm' \
  '/Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/SupportingImages/**/*'

collect notes \
  '/Users/*/Library/Group Containers/group.com.apple.notes/**/*' \
  '/Users/*/Library/Containers/com.apple.Notes/Data/Library/Notes/**/*'                  # FDA

collect sudolastrun \
  '/private/var/db/sudo/ts/**/*'

collect utmpx \
  '/private/var/run/utmpx'

collect xpdb \
  '/private/var/protected/xprotect/db/**/*'

# ---- Finalize -------------------------------------------------------------
TOTAL_OK=$(($(wc -l < "$MANIFEST") - 1))
TOTAL_FAIL=$(grep -c ',fail$' "$MANIFEST" 2>/dev/null || print 0)
log "Collection complete — items=${TOTAL_OK} fail=${TOTAL_FAIL}"
log "Output: ${OUTROOT}"

# Tarball + top-level sha256 for chain-of-custody
ARCHIVE="${OUTROOT}.zip"
log "Creating archive ${ARCHIVE} (ditto zip, preserves macOS metadata)"
ditto -c -k --sequesterRsrc --keepParent "$OUTROOT" "$ARCHIVE" 2>>"$LOG"
shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256" 2>>"$LOG"
log "Archive sha256: $(cat "${ARCHIVE}.sha256")"
log "Done."

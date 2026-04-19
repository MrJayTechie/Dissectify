from __future__ import annotations

import plistlib
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# A bplist header — binary plists stored inside ZVALUE begin with "bplist".
_BPLIST_MAGIC = b"bplist"
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _decode_property_value(val):
    """Turn a ZACCOUNTPROPERTY.ZVALUE blob into a human-readable string.

    ZVALUE is most often a bplist-encoded NSArchiver payload carrying
    UUIDs, URLs, account identifiers or serialized user names. Returning
    the raw ``<binary N bytes>`` placeholder (the old behaviour) makes the
    sheet useless; instead:

    1. Try to decode as a binary plist and, if that yields something with
       readable fields (strings, int, lists of strings), render those.
    2. Fall back to extracting printable ASCII runs, which catches URLs,
       UUIDs, and bundle identifiers embedded in NSKeyedArchiver streams.
    3. As a last resort, return the byte length so the row isn't silently
       indistinguishable from an empty one.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return val
    if not isinstance(val, bytes):
        return str(val)

    if not val:
        return ""

    # Plain UTF-8 string stored as blob
    try:
        s = val.decode("utf-8")
        if s.isprintable() or all(c == "\n" or c.isprintable() for c in s):
            return s
    except (UnicodeDecodeError, ValueError):
        pass

    # Binary plist
    if val.startswith(_BPLIST_MAGIC):
        try:
            decoded = plistlib.loads(val)
            # NSKeyedArchiver: follow $top.root UID reference into $objects
            # so we return the leaf string/value instead of the archive
            # wrapper (which always renders as "$version=100000 ...").
            unarchived = _unwrap_keyed_archive(decoded)
            rendered = _stringify_plist(unarchived)
            if rendered:
                return rendered
        except Exception:
            pass

    # Extract any embedded printable strings (URLs, UUIDs, bundle ids)
    runs = _PRINTABLE_RUN_RE.findall(val)
    if runs:
        unique = []
        seen = set()
        for r in runs:
            try:
                s = r.decode("ascii")
            except UnicodeDecodeError:
                continue
            # Skip typedstream/NSArchive framing noise
            if s in seen or s in {"NSString", "NSObject", "NSArray", "NSDictionary", "streamtyped", "$null"}:
                continue
            seen.add(s)
            unique.append(s)
            if len(unique) >= 6:
                break
        if unique:
            return " | ".join(unique)

    return f"<binary {len(val)} bytes>"


def _unwrap_keyed_archive(obj, max_depth=6):
    """If ``obj`` is an NSKeyedArchiver archive, follow ``$top.root`` through
    ``$objects`` and return the resolved leaf (str/int/dict/list). Falls
    through unchanged for plain plists or unresolvable archives."""
    if not isinstance(obj, dict):
        return obj
    if obj.get("$archiver") != "NSKeyedArchiver":
        return obj
    objects = obj.get("$objects")
    top = obj.get("$top", {})
    if not isinstance(objects, list) or not isinstance(top, dict):
        return obj
    root = top.get("root")

    def resolve(node, depth=0):
        if depth > max_depth:
            return None
        # plistlib exposes UID references as plistlib.UID; fall back to
        # duck-typing if the runtime type isn't available.
        if hasattr(node, "data"):  # plistlib.UID
            idx = node.data
            if 0 <= idx < len(objects):
                return resolve(objects[idx], depth + 1)
            return None
        if isinstance(node, str) and node == "$null":
            return None
        if isinstance(node, list):
            return [resolve(x, depth + 1) for x in node]
        if isinstance(node, dict):
            # Class descriptors carry $classname/$classes and recursively
            # describe themselves; skip them.
            if "$classname" in node or "$classes" in node:
                return node.get("$classname")
            out = {}
            for k, v in node.items():
                if k.startswith("$"):
                    continue
                out[k] = resolve(v, depth + 1)
            # NSMutableArray / NSArray serialise their members under "NS.objects"
            if "NS.objects" in node:
                return resolve(node["NS.objects"], depth + 1)
            # NSString / NSMutableString use "NS.string"
            if "NS.string" in node:
                return resolve(node["NS.string"], depth + 1)
            return out or node
        return node

    resolved = resolve(root)
    return resolved if resolved is not None else obj


def _stringify_plist(obj, depth=0):
    """Render a small plist subtree into a compact readable string."""
    if depth > 4:
        return ""
    if obj is None:
        return ""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(obj)} bytes>"
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list):
        parts = [_stringify_plist(x, depth + 1) for x in obj[:8]]
        return "[" + ", ".join(p for p in parts if p) + "]"
    if isinstance(obj, dict):
        parts = []
        for k, v in list(obj.items())[:8]:
            rendered = _stringify_plist(v, depth + 1)
            if rendered:
                parts.append(f"{k}={rendered}")
        return " ".join(parts)
    return str(obj)


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


AccountRecord = TargetRecordDescriptor(
    "macos/accounts/entries",
    [
        ("datetime", "ts_created"),
        ("string", "username"),
        ("string", "description"),
        ("string", "identifier"),
        ("string", "account_type"),
        ("string", "account_type_description"),
        ("string", "owning_bundle_id"),
        ("string", "authentication_type"),
        ("boolean", "active"),
        ("boolean", "authenticated"),
        ("boolean", "visible"),
        ("path", "source"),
    ],
)

AccountTypeRecord = TargetRecordDescriptor(
    "macos/accounts/types",
    [
        ("string", "identifier"),
        ("string", "description"),
        ("string", "owning_bundle_id"),
        ("string", "credential_type"),
        ("boolean", "supports_authentication"),
        ("boolean", "supports_multiple"),
        ("boolean", "obsolete"),
        ("path", "source"),
    ],
)

AccountPropertyRecord = TargetRecordDescriptor(
    "macos/accounts/properties",
    [
        ("string", "username"),
        ("string", "account_identifier"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

CredentialRecord = TargetRecordDescriptor(
    "macos/accounts/credentials",
    [
        ("datetime", "ts_expiration"),
        ("string", "account_identifier"),
        ("string", "service_name"),
        ("boolean", "persistent"),
        ("path", "source"),
    ],
)


class MacOSAccountsPlugin(Plugin):
    """Plugin to parse macOS Internet Accounts (Accounts4.sqlite).

    Parses configured accounts (iCloud, GameCenter, iTunes, CalDAV, CardDAV,
    FindMyFriends, etc.), account types, properties, and credentials.

    Location: ~/Library/Accounts/Accounts4.sqlite
    """

    __namespace__ = "accounts"

    ACCOUNTS_GLOB = "Users/*/Library/Accounts/Accounts4.sqlite"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.ACCOUNTS_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No Accounts4.sqlite found")

    def _open_db(self, path):
        with path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = path.parent.joinpath(path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=AccountRecord)
    def entries(self) -> Iterator[AccountRecord]:
        """Parse configured Internet Accounts."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT a.ZUSERNAME, a.ZACCOUNTDESCRIPTION, a.ZIDENTIFIER,
                           a.ZOWNINGBUNDLEID, a.ZAUTHENTICATIONTYPE,
                           a.ZACTIVE, a.ZAUTHENTICATED, a.ZVISIBLE, a.ZDATE,
                           t.ZIDENTIFIER AS type_id,
                           t.ZACCOUNTTYPEDESCRIPTION AS type_desc
                    FROM ZACCOUNT a
                    LEFT JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK
                    ORDER BY a.ZDATE DESC
                """)
                for row in cursor:
                    yield AccountRecord(
                        ts_created=_cocoa_ts(row["ZDATE"]),
                        username=row["ZUSERNAME"] or "",
                        description=row["ZACCOUNTDESCRIPTION"] or "",
                        identifier=row["ZIDENTIFIER"] or "",
                        account_type=row["type_id"] or "",
                        account_type_description=row["type_desc"] or "",
                        owning_bundle_id=row["ZOWNINGBUNDLEID"] or "",
                        authentication_type=row["ZAUTHENTICATIONTYPE"] or "",
                        active=bool(row["ZACTIVE"]),
                        authenticated=bool(row["ZAUTHENTICATED"]),
                        visible=bool(row["ZVISIBLE"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing accounts %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=AccountPropertyRecord)
    def properties(self) -> Iterator[AccountPropertyRecord]:
        """Parse account properties (key-value pairs per account)."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT p.ZKEY, p.ZVALUE,
                           a.ZUSERNAME, a.ZIDENTIFIER
                    FROM ZACCOUNTPROPERTY p
                    LEFT JOIN ZACCOUNT a ON p.ZOWNER = a.Z_PK
                    ORDER BY a.ZUSERNAME, p.ZKEY
                """)
                for row in cursor:
                    val = _decode_property_value(row["ZVALUE"])

                    yield AccountPropertyRecord(
                        username=row["ZUSERNAME"] or "",
                        account_identifier=row["ZIDENTIFIER"] or "",
                        key=row["ZKEY"] or "",
                        value=val,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing account properties %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=CredentialRecord)
    def credentials(self) -> Iterator[CredentialRecord]:
        """Parse credential items (service names, expiration — no secrets extracted)."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZACCOUNTIDENTIFIER, ZSERVICENAME,
                           ZPERSISTENT, ZEXPIRATIONDATE
                    FROM ZCREDENTIALITEM
                    ORDER BY ZEXPIRATIONDATE DESC
                """)
                for row in cursor:
                    yield CredentialRecord(
                        ts_expiration=_cocoa_ts(row["ZEXPIRATIONDATE"]),
                        account_identifier=row["ZACCOUNTIDENTIFIER"] or "",
                        service_name=row["ZSERVICENAME"] or "",
                        persistent=bool(row["ZPERSISTENT"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing credentials %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

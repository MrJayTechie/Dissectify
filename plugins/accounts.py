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
            # NSKeyedArchiver: follow $top.root UID into $objects to reach
            # the real value. Without this we render archive plumbing.
            if isinstance(decoded, dict) and decoded.get("$archiver") == "NSKeyedArchiver":
                resolved = _resolve_keyed_archive(decoded)
                if resolved is not None:
                    rendered = _stringify_plist(resolved)
                    if rendered:
                        return rendered
            rendered = _stringify_plist(decoded)
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


_NSARCHIVER_NOISE = {"$null", "$class", "$classname", "$classes"}


def _resolve_keyed_archive(archive):
    """Walk an NSKeyedArchiver dict: follow $top.root UID into $objects and
    return the resolved leaf, dereferencing nested UIDs along the way."""
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        return None
    root_uid = top.get("root")
    if not isinstance(root_uid, plistlib.UID):
        return None

    def resolve(node, seen):
        if isinstance(node, plistlib.UID):
            if node.data in seen or node.data >= len(objects):
                return None
            seen = seen | {node.data}
            target = objects[node.data]
            if isinstance(target, str) and target == "$null":
                return None
            return resolve(target, seen)
        if isinstance(node, dict):
            # NSArray / NSMutableArray: pick the NS.objects list
            if "NS.objects" in node:
                return [resolve(x, seen) for x in node["NS.objects"]]
            # NSDictionary: zip NS.keys + NS.objects
            if "NS.keys" in node and "NS.objects" in node:
                keys = [resolve(k, seen) for k in node["NS.keys"]]
                vals = [resolve(v, seen) for v in node["NS.objects"]]
                return {k: v for k, v in zip(keys, vals) if k is not None}
            # NSString / NSMutableString: NS.string carries the value
            if "NS.string" in node:
                return resolve(node["NS.string"], seen)
            # Generic dict: drop archiver framing keys
            out = {}
            for k, v in node.items():
                if k in _NSARCHIVER_NOISE or k.startswith("$"):
                    continue
                out[k] = resolve(v, seen)
            return out or None
        if isinstance(node, list):
            return [resolve(x, seen) for x in node]
        return node

    return resolve(root_uid, set())


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

    @export(record=AccountTypeRecord)
    def types(self) -> Iterator[AccountTypeRecord]:
        """Parse registered account types."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZIDENTIFIER, ZACCOUNTTYPEDESCRIPTION, ZOWNINGBUNDLEID,
                           ZCREDENTIALTYPE, ZSUPPORTSAUTHENTICATION,
                           ZSUPPORTSMULTIPLEACCOUNTS, ZOBSOLETE
                    FROM ZACCOUNTTYPE
                    ORDER BY ZIDENTIFIER
                """)
                for row in cursor:
                    yield AccountTypeRecord(
                        identifier=row["ZIDENTIFIER"] or "",
                        description=row["ZACCOUNTTYPEDESCRIPTION"] or "",
                        owning_bundle_id=row["ZOWNINGBUNDLEID"] or "",
                        credential_type=row["ZCREDENTIALTYPE"] or "",
                        supports_authentication=bool(row["ZSUPPORTSAUTHENTICATION"]),
                        supports_multiple=bool(row["ZSUPPORTSMULTIPLEACCOUNTS"]),
                        obsolete=bool(row["ZOBSOLETE"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing account types %s: %s", path, e)
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

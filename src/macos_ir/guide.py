"""Analysis Guide — loads guide metadata and builds forward + reverse indexes.

Primary source: <COLLECTORS_DIR>/GUIDE.yaml — one consolidated file keyed by
artifact stem. Produced by the collectors repo's populator tooling.

Fallback (backward-compat): inline `guide:` block inside each artifact YAML.
Most artifact YAMLs should NOT carry a guide: block because Velociraptor
rejects unknown top-level keys when building the collector.

Produces three indexes on the returned GuideIndex:
  - artifacts:       {artifact_name: GuideEntry}
  - by_category:     {category: {subcategory: [artifact_name, ...]}}
  - by_question:     {question_text: [artifact_name, ...]}
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from macos_ir.config import COLLECTORS_DIR, LIVE_COLLECTORS_DIR, GUIDE_FILE

logger = logging.getLogger(__name__)

CATEGORIES = {
    "User Activity",
    "Communications",
    "Persistence",
    "Filesystem",
    "Security Posture",
    "Network",
    "Installation / Software",
    "System",
    "Volatile / Runtime",
    "Cloud / Devices",
}

REQUIRES_TAGS = {"sudo", "fda", "slow_mode", "live"}


@dataclass
class GuideEntry:
    """One artifact's guide metadata."""
    name: str
    category: str = ""
    subcategory: str = ""
    description: str = ""
    questions: list[str] = field(default_factory=list)
    location_in_collection: str = ""
    requires: list[str] = field(default_factory=list)
    gotchas: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _parse_yaml(path: Path) -> dict | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning("Could not parse %s: %s", path, e)
        return None


def _validate(entry: GuideEntry) -> None:
    if not entry.category:
        entry.warnings.append("missing required 'category'")
    elif entry.category not in CATEGORIES:
        entry.warnings.append(f"unknown category '{entry.category}'")
    if not entry.subcategory:
        entry.warnings.append("missing required 'subcategory'")
    if not entry.description:
        entry.warnings.append("missing required 'description'")
    if not entry.questions:
        entry.warnings.append("missing required 'questions' (need >=1)")
    for req in entry.requires:
        if req not in REQUIRES_TAGS:
            entry.warnings.append(f"unknown requires tag '{req}'")


def _entry_from_dict(name: str, g: dict) -> GuideEntry:
    entry = GuideEntry(
        name=name,
        category=g.get("category", ""),
        subcategory=g.get("subcategory", ""),
        description=(g.get("description") or "").strip(),
        questions=list(g.get("questions") or []),
        location_in_collection=(g.get("location_in_collection") or "").strip(),
        requires=list(g.get("requires") or []),
        gotchas=list(g.get("gotchas") or []),
        see_also=list(g.get("see_also") or []),
    )
    _validate(entry)
    return entry


def _load_consolidated(guide_path: Path) -> dict[str, GuideEntry]:
    """Load entries from a single GUIDE.yaml keyed by artifact stem."""
    data = _parse_yaml(guide_path)
    if not isinstance(data, dict):
        return {}
    entries: dict[str, GuideEntry] = {}
    for name, g in data.items():
        if isinstance(g, dict):
            entries[name] = _entry_from_dict(name, g)
    return entries


def _load_inline(yaml_paths: list[Path]) -> dict[str, GuideEntry]:
    """Fallback: extract inline guide: blocks from artifact YAMLs."""
    entries: dict[str, GuideEntry] = {}
    for path in yaml_paths:
        data = _parse_yaml(path)
        if not data or "guide" not in data:
            continue
        g = data.get("guide")
        if not isinstance(g, dict):
            continue
        entries[path.stem] = _entry_from_dict(path.stem, g)
    return entries


@dataclass
class GuideIndex:
    artifacts: dict[str, GuideEntry] = field(default_factory=dict)
    by_category: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    by_question: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[tuple[str, str]] = field(default_factory=list)

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def annotated_count(self) -> int:
        return sum(1 for e in self.artifacts.values() if not e.warnings)

    def get(self, name: str) -> GuideEntry | None:
        return self.artifacts.get(name)

    def categories(self) -> list[str]:
        ordered = [
            "User Activity", "Communications", "Persistence", "Filesystem",
            "Security Posture", "Network", "Installation / Software",
            "System", "Volatile / Runtime", "Cloud / Devices",
        ]
        present = {c for c in self.by_category if c in CATEGORIES}
        return [c for c in ordered if c in present]

    def artifacts_for_question(self, question: str) -> list[str]:
        return self.by_question.get(question, [])

    def search_questions(self, term: str) -> list[str]:
        t = term.lower()
        return [q for q in self.by_question if t in q.lower()]

    def sample_keywords(self) -> list[str]:
        """A curated set of keywords known to hit useful questions, for UI hints."""
        # Pick terms whose substring appears in >=1 question each
        candidates = [
            "login", "command", "install", "network", "USB", "browser",
            "persistence", "launch", "kernel", "profile", "MDM", "TCC",
            "sudo", "ssh", "trash", "file", "SIP", "Gatekeeper", "FileVault",
            "iCloud", "message", "mail", "contact", "process", "socket",
            "history", "note", "shortcut", "device",
        ]
        hits = []
        for kw in candidates:
            if self.search_questions(kw):
                hits.append(kw)
        return hits


def load_all() -> GuideIndex:
    """Load from GUIDE.yaml (preferred), falling back to inline guide: blocks."""
    idx = GuideIndex()

    yaml_paths: list[Path] = []
    for d in (COLLECTORS_DIR, LIVE_COLLECTORS_DIR):
        if d.is_dir():
            yaml_paths.extend(p for p in d.glob("*.yaml") if p.stem != "spec")

    # Preferred: consolidated GUIDE.yaml under the project's guide/ dir
    consolidated: dict[str, GuideEntry] = {}
    if GUIDE_FILE.is_file():
        consolidated = _load_consolidated(GUIDE_FILE)

    # Fallback / merge: inline guide: blocks (usually empty now, present only
    # in old checkouts or user-added entries).
    inline = _load_inline(yaml_paths)

    # consolidated takes precedence over inline when both exist
    merged: dict[str, GuideEntry] = {}
    for name, e in inline.items():
        merged[name] = e
    for name, e in consolidated.items():
        merged[name] = e

    for name, entry in merged.items():
        idx.artifacts[name] = entry
        if entry.category:
            idx.by_category.setdefault(entry.category, {}).setdefault(
                entry.subcategory or "Uncategorized", []
            ).append(entry.name)
        for q in entry.questions:
            idx.by_question.setdefault(q, []).append(entry.name)
        for w in entry.warnings:
            idx.warnings.append((entry.name, w))

    for cat in idx.by_category:
        for sub in idx.by_category[cat]:
            idx.by_category[cat][sub].sort()

    return idx


def format_warnings(idx: GuideIndex, max_lines: int = 20) -> str:
    if not idx.warnings:
        return ""
    head = idx.warnings[:max_lines]
    extra = len(idx.warnings) - len(head)
    lines = [f"  {a}: {m}" for a, m in head]
    if extra > 0:
        lines.append(f"  ... and {extra} more warnings")
    return f"{len(idx.warnings)} guide warnings across {len({a for a, _ in idx.warnings})} artifacts:\n" + "\n".join(lines)

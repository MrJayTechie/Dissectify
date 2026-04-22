# Guide Metadata Schema

Every artifact YAML in this repository may include a `guide:` block describing
what forensic questions the artifact answers, what analysts should know about
it, and where to find related data. Dissectify reads this metadata to render
the **Analysis Guide** and **Search** tabs.

## Schema

```yaml
guide:
  category: User Activity              # required; must be one of the 10 below
  subcategory: Command execution       # required; free-text within category

  description: |                       # required; 1–3 sentences
    Short analyst-oriented summary of what the artifact contains.

  questions:                           # required; ≥1 interrogative questions
    - "Did the user run a specific command?"
    - "When did the user last use Terminal?"

  location_in_collection: |            # optional; where to find the parsed data
    Sheet "ShellHistoryAndSessions" in the workbook.

  requires:                            # optional; known constraints
    - sudo                             # needs root to collect
    - fda                              # needs Full Disk Access
    - slow_mode                        # gated behind the "Include Slow" toggle
    - live                             # only present in live collections

  gotchas:                             # optional; practical warnings
    - "Users can disable by unsetting HISTFILE"

  see_also:                            # optional; related artifact names
    - sudolastrun
    - KnowledgeC
```

## Closed list of `category` values

Choose exactly one. Proposing a new category requires updating this document.

| Category                | Covers |
|-------------------------|--------|
| `User Activity`         | Shell history, KnowledgeC, Biomes, browser history, recent files, Spotlight shortcuts |
| `Communications`        | Messages, Mail, contacts, calls, FaceTime, notifications |
| `Persistence`           | LaunchAgents / LaunchDaemons, login items, kext, system extensions |
| `Filesystem`            | Trash, FSEvents, DS_Store, DocumentRevisions, QuickLook |
| `Security Posture`      | TCC, Gatekeeper, SIP, FileVault, firewall, MDM profiles, XProtect |
| `Network`               | Wi-Fi, DNS, SSH, connections, routing, pf |
| `Installation / Software` | Installed apps, pkg receipts, software updates |
| `System`                | OS version, users, hostname, install date, NVRAM |
| `Volatile / Runtime`    | Processes, sockets live, kexts loaded (live only) |
| `Cloud / Devices`       | iCloud, iDevice pairing, Find My, Mobile Documents |

## Writing conventions

- **Questions** — phrase as the analyst would speak them: interrogative
  ("Did the user run X?", not "Find commands the user ran"). Include
  multiple questions when one artifact answers several.
- **Description** — factual, no opinions ("contains X" not "this is the best way to find X").
- **Gotchas** — practical warnings about data gaps, user-disable mechanisms,
  macOS version differences. Skip if none.
- **see_also** — artifacts commonly checked together during the same
  investigation. Use the YAML filename stem (e.g., `KnowledgeC`, not
  `MacOS.Collection.KnowledgeC`).

## Validation

Dissectify runs a soft validator when loading. Warnings (not hard errors) for:
- Missing required fields
- Unknown `category` values
- `see_also` references to artifacts not in the repo

"""macOS IR Workbench — Textual TUI application."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from rich.text import Text

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.suggester import Suggester
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from macos_ir.config import (
    update_plugins, update_collectors, download_velociraptor, build_collector,
    get_plugin_path, get_collector_path, get_velo_binaries, get_run_command,
    load_config, save_config,
    COLLECTORS_DIR, PLUGINS_DIR, VELO_DIR, BUILD_DIR, COLLECTED_DIR,
)
from macos_ir.health import CollectionHealth, MISSING_REASONS
from macos_ir.plugins import get_selected_functions
from macos_ir.workbook import resolve_target, run_function, write_xlsx


# ──────────────────────────────────────────────────────────────────────────────
# Path autocomplete
# ──────────────────────────────────────────────────────────────────────────────

class PathSuggester(Suggester):
    def __init__(self, dirs_only: bool = False) -> None:
        super().__init__(use_cache=False, case_sensitive=True)
        self._dirs_only = dirs_only

    async def get_suggestion(self, value: str) -> str | None:
        if not value:
            return None
        expanded = os.path.expanduser(value)
        p = Path(expanded)
        if p.is_dir() and value.endswith("/"):
            parent, partial = p, ""
        else:
            parent, partial = p.parent, p.name
        if not parent.is_dir():
            return None
        try:
            entries = sorted(parent.iterdir())
        except PermissionError:
            return None
        for entry in entries:
            if self._dirs_only and not entry.is_dir():
                continue
            if entry.name.startswith("."):
                continue
            if entry.name.lower().startswith(partial.lower()) and entry.name != partial:
                suggestion = str(parent / entry.name)
                if entry.is_dir():
                    suggestion += "/"
                if value.startswith("~"):
                    suggestion = suggestion.replace(os.path.expanduser("~"), "~", 1)
                return suggestion
        return None


class PathInput(Input):
    BINDINGS = [Binding("tab", "accept_or_focus", show=False)]

    def action_accept_or_focus(self) -> None:
        if self._suggestion:
            self.value = self._suggestion
            self.cursor_position = len(self.value)
        else:
            self.screen.focus_next()


# ──────────────────────────────────────────────────────────────────────────────
# Visual helpers
# ──────────────────────────────────────────────────────────────────────────────

def _bar(pct: float, width: int = 16) -> str:
    """Return a Unicode bar like ████████░░░░ with color markup."""
    filled = int(pct / 100 * width)
    empty = width - filled
    if pct >= 80:
        color = "green"
    elif pct >= 50:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/]"


def _build_summary_card(result: dict) -> str:
    """Build a Rich-markup summary card from health check results."""
    meta = result["metadata"]
    fda = result["fda_inference"]
    summary = result["summary"]
    artifacts = result["artifacts"]

    total = summary["total_artifacts"]
    present = summary["present"]
    pct = int(present / total * 100) if total else 0

    # FDA color
    if fda["status"] in ("GRANTED", "LIKELY_GRANTED"):
        fda_color = "green"
    elif fda["status"] in ("NOT_GRANTED", "LIKELY_NOT_GRANTED"):
        fda_color = "red"
    else:
        fda_color = "yellow"

    # Collection info
    hostname = meta.get("hostname", "UNKNOWN")
    os_ver = meta.get("os_version", "N/A")
    users = ", ".join(result.get("users", [])) or "none"
    coll_date = meta.get("collection_date", "N/A")

    lines = [
        "",
        f"  [bold cyan]Collection Summary[/]",
        "",
        f"  [bold]Hostname:[/]    {hostname}",
        f"  [bold]OS:[/]          {os_ver}",
        f"  [bold]Users:[/]       {users}",
        f"  [bold]Collected:[/]   {coll_date}",
        "",
        f"  [bold]Overall:[/]  {present}/{total}  {_bar(pct)}  {pct}%",
        f"  [bold]FDA:[/]         [{fda_color}]{fda['status']}[/] ({fda['confidence']})",
        "",
    ]

    # Per-category breakdown
    categories: dict[str, dict] = {}
    for name, info in artifacts.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = {"present": 0, "total": 0}
        categories[cat]["total"] += 1
        if info["status"] == "PRESENT":
            categories[cat]["present"] += 1

    lines.append("  [bold]Category Breakdown:[/]")
    for cat in sorted(categories):
        cp = categories[cat]["present"]
        ct = categories[cat]["total"]
        cat_pct = int(cp / ct * 100) if ct else 0
        lines.append(
            f"    {cat:<16} {cp:>2}/{ct:<2}  {_bar(cat_pct, 12)}  {cat_pct:>3}%"
        )

    # Recommendations
    recs = result.get("recommendations", [])
    if recs:
        lines.append("")
        lines.append("  [bold]Recommendations:[/]")
        for r in recs:
            icon = {
                "OK": "[green]OK[/]",
                "WARN": "[yellow]WARN[/]",
                "CRITICAL": "[red]CRIT[/]",
                "INFO": "[cyan]INFO[/]",
            }.get(r["level"], r["level"])
            lines.append(f"    {icon}  {r['message']}")

    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

LOGO = r"""[bold cyan]
     ____  _                     _   _  __
    |  _ \(_)___ ___  ___  ___| |_(_)/ _|_   _
    | | | | / __/ __|/ _ \/ __| __| | |_| | | |
    | |_| | \__ \__ \  __/ (__| |_| |  _| |_| |
    |____/|_|___/___/\___|\___|\__|_|_|  \__, |
                                          |___/[/]
[dim]     macOS Forensic Analysis Toolkit  v1.0[/]
[dim]     by Ali Jammal[/]
[italic dim]     "Every artifact tells a story. Every byte holds a truth."[/]
"""


class MacOSIRApp(App):
    TITLE = "Dissectify"
    SUB_TITLE = "macOS Forensic Analysis Toolkit"

    CSS = """
    Screen {
        layout: vertical;
        background: $surface;
        overflow-y: auto;
    }

    #logo {
        height: auto;
        padding: 0 2;
        background: $boost;
    }

    #config-panel {
        height: auto;
        padding: 0 1;
        background: $boost;
        border: solid $primary;
        margin: 0 1 0 1;
    }

    #config-panel Label {
        width: 14;
        padding: 0 1;
        text-style: bold;
    }

    .config-row {
        height: 3;
        layout: horizontal;
    }

    .config-row Input {
        width: 1fr;
    }

    #button-bar {
        height: auto;
        layout: horizontal;
        padding: 0 1;
        margin: 0 1;
        align: center middle;
    }

    #button-bar Button {
        margin: 0 1;
        min-width: 12;
    }

    .step-label {
        height: 1;
        padding: 0 2;
        margin: 0 1 0 1;
        color: $text;
    }

    #button-bar-2 {
        height: auto;
        layout: horizontal;
        padding: 0 1;
        margin: 0 1;
        align: center middle;
    }

    #button-bar-2 Button {
        margin: 0 1;
        min-width: 12;
    }

    #button-bar-3 {
        height: auto;
        layout: horizontal;
        padding: 0 1;
        margin: 0 1;
        align: center middle;
    }

    #button-bar-3 Button {
        margin: 0 1;
        min-width: 12;
    }

    #results-tabs {
        height: 1fr;
        margin: 0 1;
        display: none;
    }

    #results-tabs.visible {
        display: block;
    }

    #summary-card {
        height: 1fr;
        overflow-y: auto;
    }

    #health-table {
        height: 1fr;
    }

    #parse-log {
        height: 1fr;
    }

    #progress-row {
        height: 3;
        layout: horizontal;
        padding: 0 1;
    }

    #progress-row ProgressBar {
        width: 1fr;
    }

    #progress-label {
        width: 30;
        padding: 0 1;
    }

    #parse-log {
        height: 1fr;
    }

    #status-bar {
        height: 1;
        padding: 0 1;
        background: $boost;
        color: $text-muted;
    }

    .section-title {
        text-style: bold;
        color: $text;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+h", "health_check", "Health Check"),
        Binding("ctrl+g", "generate", "Generate Workbook"),
        Binding("ctrl+o", "open_xlsx", "Open XLSX"),
    ]

    def __init__(self):
        super().__init__()
        self._health_result: dict | None = None
        self._xlsx_path: str | None = None
        self._cfg = load_config()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(LOGO, id="logo", markup=True)

        with Vertical(id="config-panel"):
            with Horizontal(classes="config-row"):
                yield Label("Collection:")
                yield PathInput(
                    placeholder="/path/to/collection  (Tab to autocomplete)",
                    id="collection-input",
                    value=self._cfg.get("collection_path", ""),
                    suggester=PathSuggester(dirs_only=True),
                )
            with Horizontal(classes="config-row"):
                yield Label("Plugin Path:")
                yield PathInput(
                    placeholder="Auto-detected or /path/to/plugins  (Tab to autocomplete)",
                    id="plugin-input",
                    value=self._cfg.get("plugin_path", ""),
                    suggester=PathSuggester(dirs_only=True),
                )
            with Horizontal(classes="config-row"):
                yield Label("Output XLSX:")
                yield Input(
                    value=self._cfg.get("output_path", "artifacts.xlsx"),
                    id="output-input",
                )

        yield Static(
            "[bold cyan]STEP 1:[/] Setup — Download Tools & Updates",
            classes="step-label",
        )
        with Horizontal(id="button-bar"):
            yield Button("Download Velociraptor", id="btn-velo", variant="default")
            yield Button("Update Plugins", id="btn-update", variant="default")
            yield Button("Update Collectors", id="btn-collectors", variant="default")

        yield Static(
            "[bold cyan]STEP 2:[/] Collect — Build & Deploy Collector",
            classes="step-label",
        )
        with Horizontal(id="button-bar-2"):
            yield Button("Build Intel", id="btn-build-amd64", variant="success")
            yield Button("Build Apple Silicon", id="btn-build-arm64", variant="success")
            yield Button("Collector Guide", id="btn-guide", variant="default")
            yield Button("Copy Commands", id="btn-copy", variant="default")

        yield Static(
            "[bold cyan]STEP 3:[/] Analyze — Health Check & Export",
            classes="step-label",
        )
        with Horizontal(id="button-bar-3"):
            yield Button("Health Check", id="btn-health", variant="primary")
            yield Button("Generate Workbook", id="btn-generate", variant="success", disabled=True)
            yield Button("Open XLSX", id="btn-open", variant="default", disabled=True)
            yield Button("Include Slow", id="btn-slow", variant="warning")

        with TabbedContent(id="results-tabs"):
            with TabPane("Summary", id="tab-summary"):
                yield RichLog(id="summary-card", highlight=True, markup=True)
            with TabPane("Artifacts", id="tab-artifacts"):
                yield DataTable(id="health-table")
            with TabPane("Parse", id="tab-parse"):
                with Horizontal(id="progress-row"):
                    yield ProgressBar(id="progress-bar", total=100)
                    yield Label("Ready", id="progress-label")
                yield RichLog(id="parse-log", highlight=True, markup=True)
            with TabPane("Collector", id="tab-collector"):
                yield RichLog(id="collector-log", highlight=True, markup=True)

        yield Static("Ready  |  Hold Option + drag to select text, then Cmd+C to copy", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#health-table", DataTable)
        table.add_columns("Artifact", "Status", "Category", "Privilege", "Reason")
        table.cursor_type = "row"

        # Auto-detect plugin path
        plugin_input = self.query_one("#plugin-input", Input)
        if not plugin_input.value.strip():
            detected = get_plugin_path(self._cfg)
            if detected:
                plugin_input.value = detected
                self._set_status(f"Plugins auto-detected: {detected}")
            else:
                self._set_status("No plugins found — click 'Update Plugins' to download from GitHub")

    # ── Helpers ──

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

    def _set_btn(self, btn_id: str, disabled: bool) -> None:
        self.query_one(f"#{btn_id}", Button).disabled = disabled

    def _save_paths(self) -> None:
        """Persist current paths for next session."""
        self._cfg["collection_path"] = self.query_one("#collection-input", Input).value.strip()
        self._cfg["plugin_path"] = self.query_one("#plugin-input", Input).value.strip()
        self._cfg["output_path"] = self.query_one("#output-input", Input).value.strip()
        save_config(self._cfg)

    # ── Button handlers ──

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-health":
            self.action_health_check()
        elif event.button.id == "btn-generate":
            self.action_generate()
        elif event.button.id == "btn-open":
            self.action_open_xlsx()
        elif event.button.id == "btn-slow":
            if event.button.variant == "warning":
                event.button.variant = "success"
                event.button.label = "Slow: ON"
            else:
                event.button.variant = "warning"
                event.button.label = "Include Slow"
        elif event.button.id == "btn-update":
            self._do_update_plugins()
        elif event.button.id == "btn-collectors":
            self._do_update_collectors()
        elif event.button.id == "btn-velo":
            self._do_download_velo()
        elif event.button.id == "btn-build-amd64":
            self._do_build_collector("amd64")
        elif event.button.id == "btn-build-arm64":
            self._do_build_collector("arm64")
        elif event.button.id == "btn-guide":
            self._show_collector_guide()
        elif event.button.id == "btn-copy":
            self._copy_commands()

    # ── Plugin update ──

    @work(thread=True, exclusive=True)
    def _do_update_plugins(self) -> None:
        self.call_from_thread(self._set_btn, "btn-update", True)
        self.call_from_thread(self._show_collector_log)

        log = self.query_one("#collector-log", RichLog)
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, "[bold cyan]Updating Plugins from GitHub[/]\n")
        self.call_from_thread(log.write, "  [dim]Cloning repository...[/]")
        self.call_from_thread(self._set_status, "Cloning plugin repository...")

        path, err = update_plugins()

        if err:
            self.call_from_thread(log.write, f"  [red]Error: {err}[/]")
            self.call_from_thread(self.notify, f"Plugin update error: {err}", severity="error")
        if path:
            count = len(list(PLUGINS_DIR.glob("*.py")))
            self.call_from_thread(log.write, f"  [green]Updated: {count} plugins[/]")
            self.call_from_thread(self._on_plugins_downloaded, path)
        else:
            self.call_from_thread(self._set_status, f"Plugin update failed: {err}")

        self.call_from_thread(self._set_btn, "btn-update", False)

    def _on_plugins_downloaded(self, path: str) -> None:
        self.query_one("#plugin-input", Input).value = path
        self._cfg["plugin_path"] = path
        save_config(self._cfg)
        self._set_status(f"Plugins updated: {path}")
        self.notify("Plugins updated", severity="information")

    # ── Collector update ──

    @work(thread=True, exclusive=True)
    def _do_update_collectors(self) -> None:
        self.call_from_thread(self._set_btn, "btn-collectors", True)
        self.call_from_thread(self._show_collector_log)

        log = self.query_one("#collector-log", RichLog)
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, "[bold cyan]Updating Collectors from GitHub[/]\n")
        self.call_from_thread(log.write, "  [dim]Cloning repository...[/]")
        self.call_from_thread(self._set_status, "Cloning collector repository...")

        path, err = update_collectors()

        if err:
            self.call_from_thread(log.write, f"  [red]Error: {err}[/]")
            self.call_from_thread(self.notify, f"Collector update error: {err}", severity="error")
        if path:
            count = len(list(COLLECTORS_DIR.glob("*.yaml")))
            self.call_from_thread(log.write, f"  [green]Updated: {count} YAML collectors[/]")
            self.call_from_thread(self._set_status, f"Collectors updated: {count} YAML files")
            self.call_from_thread(self.notify, f"Collectors updated: {count} YAML files", severity="information")
        else:
            self.call_from_thread(self._set_status, f"Collector update failed: {err}")

        self.call_from_thread(self._set_btn, "btn-collectors", False)

    # ── Velociraptor download ──

    def _show_collector_log(self) -> None:
        """Show the collector tab."""
        tabs = self.query_one("#results-tabs", TabbedContent)
        tabs.add_class("visible")
        tabs.active = "tab-collector"

    @work(thread=True, exclusive=True)
    def _do_download_velo(self) -> None:
        self.call_from_thread(self._set_btn, "btn-velo", True)
        self.call_from_thread(self._show_collector_log)

        log = self.query_one("#collector-log", RichLog)
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, "[bold cyan]Downloading Velociraptor Binaries[/]\n")

        last_pct = [-1]

        def _progress(arch, received, total, msg):
            self.call_from_thread(self._set_status, msg)
            if total > 0:
                pct = int(received / total * 100)
                if pct % 10 == 0 and pct != last_pct[0]:
                    last_pct[0] = pct
                    mb_recv = received / (1024 * 1024)
                    mb_total = total / (1024 * 1024)
                    bar = _bar(pct, 20)
                    self.call_from_thread(
                        log.write,
                        f"  {arch}  {bar}  {mb_recv:.1f}/{mb_total:.1f} MB  ({pct}%)"
                    )

        path, err = download_velociraptor(progress_cb=_progress)

        if err and not path:
            self.call_from_thread(log.write, f"\n[red]Download failed: {err}[/]")
            self.call_from_thread(self._set_status, f"Download failed: {err}")
        elif path:
            self.call_from_thread(log.write, "")
            binaries = get_velo_binaries()
            for b in binaries:
                size_mb = b.stat().st_size / (1024 * 1024)
                self.call_from_thread(
                    log.write, f"  [green]{b.name}[/]  ({size_mb:.1f} MB)"
                )
            self.call_from_thread(
                self._set_status,
                f"Downloaded {len(binaries)} binaries to velociraptor/"
            )
            self.call_from_thread(
                self.notify,
                f"Downloaded {len(binaries)} binaries",
                severity="information",
            )
            if err:
                self.call_from_thread(self.notify, f"Partial error: {err}", severity="warning")

        self.call_from_thread(self._set_btn, "btn-velo", False)

    # ── Build collector ──

    @work(thread=True, exclusive=True)
    def _do_build_collector(self, arch: str) -> None:
        label = "Apple Silicon" if arch == "arm64" else "Intel"
        btn_id = f"btn-build-{arch}"

        self.call_from_thread(self._set_status, f"Building {label} collector...")
        self.call_from_thread(self._set_btn, btn_id, True)

        # Show progress in the collector tab
        self.call_from_thread(self.query_one("#results-tabs", TabbedContent).add_class, "visible")
        log = self.query_one("#collector-log", RichLog)
        self.call_from_thread(log.clear)
        self.call_from_thread(log.write, f"[bold cyan]Building {label} ({arch}) Collector[/]\n")

        def _progress(msg):
            self.call_from_thread(log.write, f"  [dim]{msg}[/]")
            self.call_from_thread(self._set_status, msg)

        built, errors = build_collector(arch=arch, progress_cb=_progress)

        if built:
            collector_path = built[0]
            # Find the velociraptor binary for this arch
            velo_bins = get_velo_binaries()
            velo_bin = next((b for b in velo_bins if arch in b.name), None)
            velo_name = velo_bin.name if velo_bin else f"velociraptor-darwin-{arch}"

            self.call_from_thread(log.write, "")
            self.call_from_thread(log.write, f"[bold green]Built successfully:[/]")
            self.call_from_thread(log.write, f"  [green]{collector_path}[/]")
            self.call_from_thread(log.write, "")

            self.call_from_thread(log.write, "[bold]To collect from a target Mac:[/]")
            self.call_from_thread(
                log.write,
                f"  [green]sudo ./{velo_name} -- --embedded_config {collector_path}[/]"
            )
            self.call_from_thread(log.write, "")

            self.call_from_thread(log.write, "[bold]Then extract the collection (pick one):[/]")
            self.call_from_thread(log.write, "")
            self.call_from_thread(log.write, "  [cyan]Option A — bsdtar (recommended):[/]")
            self.call_from_thread(log.write, "  [green]bsdtar -xf <collection>.zip -C /path/to/output[/]")
            self.call_from_thread(log.write, "")
            self.call_from_thread(log.write, "  [cyan]Option B — ditto (macOS native):[/]")
            self.call_from_thread(log.write, "  [green]ditto -xk <collection>.zip /path/to/output[/]")
            self.call_from_thread(log.write, "")
            self.call_from_thread(log.write, "  [yellow]Important: Always extract to APFS, never exFAT[/]")
            self.call_from_thread(log.write, "")
            self.call_from_thread(log.write, "  Then point Dissectify's Collection path at the extracted folder")
            self.call_from_thread(
                self._set_status,
                f"Collector built: {', '.join(Path(p).name for p in built)}"
            )
            self.call_from_thread(
                self.notify,
                f"{label} collector built in builds/",
                severity="information",
            )

        for e in errors:
            self.call_from_thread(log.write, f"\n  [red]ERROR: {e}[/]")

        if not built and errors:
            self.call_from_thread(self._set_status, f"Build failed: {errors[0]}")
            self.call_from_thread(self.notify, f"Build failed: {errors[0]}", severity="error")

        self.call_from_thread(self._set_btn, btn_id, False)
        self.call_from_thread(
            setattr, self.query_one("#results-tabs", TabbedContent), "active", "tab-collector"
        )

    # ── Copy commands to clipboard ──

    def _copy_commands(self) -> None:
        """Copy collector run commands to clipboard via pbcopy."""
        binaries = get_velo_binaries()
        if not binaries:
            self.notify("No Velociraptor binaries downloaded yet", severity="warning")
            return

        lines = ["# Dissectify — Collector Commands", ""]

        for b in binaries:
            arch = "arm64" if "arm64" in b.name else "amd64"
            collector = BUILD_DIR / f"Collector-darwin-{arch}"
            if collector.exists():
                lines.append(f"# Run collector ({arch}):")
                lines.append(f"sudo ./{b.name} -- --embedded_config {collector}")
                lines.append("")

        if not any((BUILD_DIR / f"Collector-darwin-{('arm64' if 'arm64' in b.name else 'amd64')}").exists() for b in binaries):
            lines.append("# No collectors built yet — click Build Intel or Build Apple Silicon first")
            lines.append("")

        lines.extend([
            "# Extract collection (pick one):",
            "bsdtar -xf <collection>.zip -C /path/to/output",
            "ditto -xk <collection>.zip /path/to/output",
            "",
            "# Important: Always extract to APFS, never exFAT",
        ])

        text = "\n".join(lines)
        try:
            proc = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            proc.communicate(text.encode())
            self.notify("Commands copied to clipboard", severity="information")
            self._set_status("Commands copied to clipboard")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    # ── Collector guide ──

    def _show_collector_guide(self) -> None:
        """Show collection commands in the Collector tab."""
        tabs = self.query_one("#results-tabs", TabbedContent)
        tabs.add_class("visible")
        tabs.active = "tab-collector"

        log = self.query_one("#collector-log", RichLog)
        log.clear()

        collector_dir = get_collector_path() or str(COLLECTORS_DIR)
        spec_path = str(COLLECTORS_DIR / "spec.yaml")
        yaml_count = len(list(COLLECTORS_DIR.glob("*.yaml"))) - 1  # exclude spec.yaml

        log.write("[bold cyan]Velociraptor Collection Guide[/]\n")
        log.write(f"[bold]Collectors:[/]  {collector_dir}  ({yaml_count} artifacts)")
        log.write(f"[bold]Spec:[/]        {spec_path}")

        # Show downloaded binaries if any
        binaries = get_velo_binaries()
        if binaries:
            log.write(f"[bold]Binaries:[/]    {VELO_DIR}/")
            for b in binaries:
                log.write(f"               [green]{b.name}[/]")
            log.write("")
        else:
            log.write(f"[bold]Binaries:[/]    [yellow]Not downloaded yet — click 'Download Velociraptor'[/]\n")

        log.write("[bold]Step 1: Download Velociraptor[/]")
        log.write("  Click 'Download Velociraptor' in Step 1 above, or manually from:")
        log.write("  [cyan]https://github.com/Velocidex/velociraptor/releases[/]\n")

        log.write("[bold]Step 2: Build the collector[/]")
        log.write("  Click 'Build Intel' or 'Build Apple Silicon' in Step 2 above")
        log.write("  This auto-generates spec.yaml and builds the collector binary\n")

        log.write("[bold]Step 3: Run on the target Mac[/]")
        if binaries:
            for b in binaries:
                arch = "arm64" if "arm64" in b.name else "amd64"
                collector = BUILD_DIR / f"Collector-darwin-{arch}"
                if collector.exists():
                    log.write(f"  [green]sudo ./{b.name} -- --embedded_config {collector}[/]")
            if not any((BUILD_DIR / f"Collector-darwin-{'arm64' if 'arm64' in b.name else 'amd64'}").exists() for b in binaries):
                log.write("  [yellow]Build a collector first (Step 2)[/]")
        else:
            log.write("  [yellow]Download Velociraptor first (Step 1)[/]")
        log.write("  [dim]This creates a .zip collection in the output directory[/]\n")

        log.write("[bold]Step 4: Extract the collection[/]")
        log.write("")
        log.write("  [cyan]Option A — bsdtar (recommended):[/]")
        log.write("  [green]bsdtar -xf <collection>.zip -C /path/to/output[/]")
        log.write("")
        log.write("  [cyan]Option B — ditto (macOS native):[/]")
        log.write("  [green]ditto -xk <collection>.zip /path/to/output[/]")
        log.write("")

        log.write("[bold]Step 5: Analyze with Dissectify[/]")
        log.write("  Point the Collection path at the extracted folder")
        log.write("  Run Health Check, then Generate Workbook\n")

        log.write("[bold yellow]Important:[/]")
        log.write("  - Grant Full Disk Access (FDA) to Terminal before running the collector")
        log.write("  - Run with sudo for maximum artifact coverage")
        log.write("  - Extract to APFS, never exFAT")

    # ── Health check ──

    def action_health_check(self) -> None:
        collection = self.query_one("#collection-input", Input).value.strip()
        if not collection:
            self.notify("Enter a collection path first", severity="warning")
            return
        expanded = os.path.expanduser(collection)
        if collection != "local" and not Path(expanded).exists():
            self.notify(f"Path not found: {collection}", severity="error")
            return
        self._save_paths()
        self._set_btn("btn-health", True)
        self._set_status("Running health check...")
        self._do_health_check(expanded)

    @work(thread=True, exclusive=True)
    def _do_health_check(self, collection_dir: str) -> None:
        try:
            health = CollectionHealth(collection_dir)
            result = health.run()
            self._health_result = result
            self.call_from_thread(self._show_health, result)
        except Exception as e:
            self.call_from_thread(self.notify, f"Health check failed: {e}", severity="error")
            self.call_from_thread(self._set_btn, "btn-health", False)
            self.call_from_thread(self._set_status, f"Error: {e}")

    def _show_health(self, result: dict) -> None:
        self._set_btn("btn-health", False)
        summary = result["summary"]

        # Show the tabbed panel
        tabs = self.query_one("#results-tabs", TabbedContent)
        tabs.add_class("visible")

        # ── Summary tab ──
        card = self.query_one("#summary-card", RichLog)
        card.clear()
        card.write(_build_summary_card(result))

        # ── Artifacts tab — color-coded detail table ──
        table = self.query_one("#health-table", DataTable)
        table.clear()
        for name, info in sorted(
            result["artifacts"].items(),
            key=lambda x: (x[1]["category"], x[1]["status"] != "PRESENT", x[0]),
        ):
            status = info["status"]
            reason = MISSING_REASONS.get(name, "") if status == "MISSING" else ""
            if status == "PRESENT":
                styled_status = Text("PRESENT", style="bold green")
            else:
                styled_status = Text("MISSING", style="bold red")
            table.add_row(name, styled_status, info["category"], info["privilege"], reason)

        # Auto-switch to summary tab
        tabs.active = "tab-summary"

        self._set_btn("btn-generate", False)
        self._set_status(
            f"Health check complete: {summary['present']}/{summary['total_artifacts']} present, "
            f"FDA: {summary['fda_status']}"
        )

    # ── Workbook generation ──

    def action_generate(self) -> None:
        collection = self.query_one("#collection-input", Input).value.strip()
        plugin_path = self.query_one("#plugin-input", Input).value.strip()
        output = self.query_one("#output-input", Input).value.strip()

        if not collection:
            self.notify("Enter a collection path", severity="warning")
            return
        if not plugin_path:
            self.notify("Enter a plugin path or click 'Update Plugins'", severity="warning")
            return
        expanded_plugin = os.path.expanduser(plugin_path)
        if not Path(expanded_plugin).is_dir():
            self.notify(f"Plugin dir not found: {plugin_path}", severity="error")
            return
        if not output:
            self.notify("Enter an output path", severity="warning")
            return

        self._save_paths()
        self._set_btn("btn-generate", True)
        self._set_btn("btn-health", True)
        self._set_status("Starting workbook generation...")

        expanded_coll = os.path.expanduser(collection)
        self._do_generate(expanded_coll, expanded_plugin, output)

    @work(thread=True, exclusive=True)
    def _do_generate(self, collection_dir: str, plugin_path: str, output: str) -> None:
        try:
            self._do_generate_inner(collection_dir, plugin_path, output)
        except Exception as e:
            self.call_from_thread(self.notify, f"Generate failed: {e}", severity="error")
            self.call_from_thread(self._finish_generate, None)

    def _do_generate_inner(self, collection_dir: str, plugin_path: str, output: str) -> None:
        # Show tabs and switch to Parse tab
        self.call_from_thread(self.query_one("#results-tabs", TabbedContent).add_class, "visible")
        self.call_from_thread(setattr, self.query_one("#results-tabs", TabbedContent), "active", "tab-parse")

        log = self.query_one("#parse-log", RichLog)
        self.call_from_thread(log.clear)

        include_slow = self.query_one("#btn-slow", Button).variant == "success"
        selected = get_selected_functions(include_slow=include_slow)
        total = len(selected)
        target = resolve_target(collection_dir)

        self.call_from_thread(self._set_progress, 0, total, "Starting...")
        self.call_from_thread(
            log.write,
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Plugins:[/bold] {plugin_path}\n"
            f"[bold]Functions:[/bold] {total}"
            + (" [yellow](slow included)[/yellow]" if include_slow else "")
            + "\n",
        )

        t0 = time.time()
        per_source: list[tuple] = []
        all_records: list[tuple[str, list[dict]]] = []

        for i, (func, category) in enumerate(selected, 1):
            self.call_from_thread(self._set_progress, i - 1, total, func)
            self.call_from_thread(self._set_status, f"[{i}/{total}] {func}")

            records, err = run_function(func, target, plugin_path, timeout=600)

            if records is None:
                self.call_from_thread(log.write, f"  [magenta]TIMEOUT[/]  {func}")
                per_source.append((func, category, 0, "timeout"))
                continue

            if err and records == []:
                if err == "incompat":
                    self.call_from_thread(log.write, f"  [dim]INCOMPAT[/]  {func}")
                else:
                    self.call_from_thread(log.write, f"  [red]ERROR[/]    {func}  {err[:60]}")
                per_source.append((func, category, 0, err))
                continue

            n = len(records)
            if n:
                all_records.append((func, records))
                self.call_from_thread(log.write, f"  [green]{n:>6,}[/]  {func}")
            else:
                self.call_from_thread(log.write, f"  [dim]     0[/]  {func}")
            per_source.append((func, category, n, None))

            self.call_from_thread(self._set_progress, i, total, func)

        # Write XLSX
        self.call_from_thread(self._set_status, "Writing XLSX...")
        self.call_from_thread(self._set_progress, total, total, "Writing XLSX...")

        try:
            write_xlsx(per_source, all_records, output)
        except Exception as e:
            self.call_from_thread(log.write, f"\n[red]XLSX failed: {type(e).__name__}: {e}[/red]")
            self.call_from_thread(self._finish_generate, None)
            return

        elapsed = time.time() - t0
        total_records = sum(p[2] for p in per_source)
        mins, secs = int(elapsed) // 60, int(elapsed) % 60
        sheets = len(all_records) + 1

        self.call_from_thread(
            log.write,
            f"\n[bold]Total records:[/bold]  {total_records:,}  "
            f"({len(all_records)} artifacts with data)\n"
            f"[bold]XLSX:[/bold]           {output}  ({sheets} sheets)\n"
            f"[bold]Elapsed:[/bold]        {mins}m {secs}s",
        )

        top = sorted([(p[0], p[2]) for p in per_source if p[2]], key=lambda x: -x[1])[:10]
        if top:
            self.call_from_thread(log.write, "\n[bold]Top 10 sources:[/bold]")
            for name, n in top:
                self.call_from_thread(log.write, f"  {name:<40} {n:>8,} records")

        self.call_from_thread(
            self._set_status,
            f"Done: {total_records:,} records, {sheets} sheets, {mins}m {secs}s",
        )
        self.call_from_thread(self._finish_generate, output)

    def _finish_generate(self, xlsx_path: str | None) -> None:
        self._xlsx_path = xlsx_path
        self._set_btn("btn-generate", False)
        self._set_btn("btn-health", False)
        if xlsx_path:
            self._set_btn("btn-open", False)

    def _set_progress(self, current: int, total: int, label: str) -> None:
        bar = self.query_one("#progress-bar", ProgressBar)
        bar.update(total=total, progress=current)
        self.query_one("#progress-label", Label).update(f"[{current}/{total}] {label}")

    # ── Open XLSX ──

    def action_open_xlsx(self) -> None:
        if not self._xlsx_path:
            self.notify("No XLSX file generated yet", severity="warning")
            return
        p = Path(self._xlsx_path)
        if not p.exists():
            self.notify(f"File not found: {self._xlsx_path}", severity="error")
            return
        try:
            subprocess.Popen(["open", str(p.resolve())])
            self._set_status(f"Opened {self._xlsx_path}")
        except Exception as e:
            self.notify(f"Failed to open: {e}", severity="error")

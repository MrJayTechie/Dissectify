"""Persistent config — remembers paths across sessions and manages plugin/collector updates."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path

CONFIG_DIR = Path.home() / ".macos-ir"
CONFIG_FILE = CONFIG_DIR / "config.json"

# GitHub repos
PLUGINS_REPO = "https://github.com/MrJayTechie/Dissect-MacOS-Plugins.git"
PLUGINS_SUBDIR = "Plugins"
COLLECTORS_REPO = "https://github.com/MrJayTechie/MacOS-Velociraptor-Collectors.git"
COLLECTORS_SUBDIR = "Collectors"


def _find_project_root() -> Path:
    """Walk up from this file to find the project root (where pyproject.toml lives)."""
    p = Path(__file__).resolve().parent
    for _ in range(10):
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    # Fallback: two levels up from macos_ir package
    return Path(__file__).resolve().parent.parent.parent


PROJECT_ROOT = _find_project_root()
PLUGINS_DIR = PROJECT_ROOT / "plugins"
COLLECTORS_DIR = PROJECT_ROOT / "collectors"


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    _ensure_dir()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    _ensure_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def get_plugin_path(cfg: dict) -> str | None:
    if PLUGINS_DIR.is_dir() and any(PLUGINS_DIR.glob("*.py")):
        return str(PLUGINS_DIR)
    return None


def get_collector_path() -> str | None:
    if COLLECTORS_DIR.is_dir() and any(COLLECTORS_DIR.glob("*.yaml")):
        return str(COLLECTORS_DIR)
    return None


# ── GitHub update helpers ──

def _clone_and_sync(repo_url: str, subdir: str, target: Path, glob: str) -> tuple[str | None, str | None]:
    """Clone a repo, copy matching files from subdir into target, return (path, error)."""
    _ensure_dir()
    tmp = CONFIG_DIR / "_update_tmp"

    try:
        if tmp.exists():
            shutil.rmtree(tmp)

        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(tmp)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return None, result.stderr.strip()[:200]

        source = tmp / subdir
        if not source.is_dir():
            return None, f"Clone OK but {subdir}/ not found in repo"

        # Clear target and copy fresh files
        if target.exists():
            # Only remove matching files, keep other files like spec.yaml
            for f in target.glob(glob):
                f.unlink()
        else:
            target.mkdir(parents=True)

        for f in source.glob(glob):
            shutil.copy2(f, target / f.name)

        return str(target), None

    except FileNotFoundError:
        return None, "git not installed"
    except subprocess.TimeoutExpired:
        return None, "git clone timed out"
    except Exception as e:
        return None, str(e)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


def update_plugins() -> tuple[str | None, str | None]:
    """Pull latest plugins from GitHub into plugins/."""
    return _clone_and_sync(PLUGINS_REPO, PLUGINS_SUBDIR, PLUGINS_DIR, "*.py")


def update_collectors() -> tuple[str | None, str | None]:
    """Pull latest YAML collectors from GitHub into collectors/."""
    return _clone_and_sync(COLLECTORS_REPO, COLLECTORS_SUBDIR, COLLECTORS_DIR, "*.yaml")


# ── Velociraptor binary download ──

VELO_DIR = PROJECT_ROOT / "velociraptor"


def download_velociraptor(progress_cb=None) -> tuple[str | None, str | None]:
    """Download latest darwin amd64 + arm64 binaries from Velocidex releases.

    progress_cb(arch, downloaded_bytes, total_bytes) is called during download.
    Returns (directory_path, error).
    """
    import json as _json
    import urllib.request

    VELO_DIR.mkdir(parents=True, exist_ok=True)

    if progress_cb:
        progress_cb("", 0, 0, "Fetching latest release info...")

    # Get latest release info
    api_url = "https://api.github.com/repos/Velocidex/velociraptor/releases/latest"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "Dissectify"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = _json.loads(resp.read())
    except Exception as e:
        return None, f"Failed to fetch release info: {e}"

    # Find the latest darwin binaries (skip .sig files)
    darwin_assets = []
    for asset in release.get("assets", []):
        name = asset["name"]
        if "darwin" in name and not name.endswith(".sig"):
            darwin_assets.append(asset)

    if not darwin_assets:
        return None, "No darwin binaries found in latest release"

    # Keep only the highest version for each arch
    best: dict[str, dict] = {}
    for asset in darwin_assets:
        name = asset["name"]
        arch = "arm64" if "arm64" in name else "amd64"
        if arch not in best or name > best[arch]["name"]:
            best[arch] = asset

    errors = []
    downloaded = []
    for arch, asset in sorted(best.items()):
        dest = VELO_DIR / asset["name"]
        if dest.exists():
            downloaded.append(str(dest))
            if progress_cb:
                progress_cb(arch, 1, 1, f"{arch}: already downloaded")
            continue

        total_size = asset.get("size", 0)
        if progress_cb:
            progress_cb(arch, 0, total_size, f"Downloading {arch}...")

        try:
            req = urllib.request.Request(
                asset["browser_download_url"],
                headers={"User-Agent": "Dissectify"},
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                chunk_size = 65536
                received = 0
                with open(str(dest), "wb") as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                        if progress_cb:
                            progress_cb(arch, received, total_size, f"Downloading {arch}...")

            dest.chmod(0o755)
            downloaded.append(str(dest))
            if progress_cb:
                progress_cb(arch, total_size, total_size, f"{arch}: done")
        except Exception as e:
            errors.append(f"{arch}: {e}")
            if dest.exists():
                dest.unlink()

    if errors and not downloaded:
        return None, "; ".join(errors)

    err = "; ".join(errors) if errors else None
    return str(VELO_DIR), err


def get_velo_binaries() -> list[Path]:
    """Return list of downloaded velociraptor binaries."""
    if not VELO_DIR.is_dir():
        return []
    return sorted([f for f in VELO_DIR.iterdir() if f.name.startswith("velociraptor") and f.is_file()])


# ── Build collector ──

BUILD_DIR = PROJECT_ROOT / "builds"
COLLECTED_DIR = PROJECT_ROOT / "collected-artifacts"


def _generate_spec() -> Path:
    """Auto-generate spec.yaml from YAML files in collectors/."""
    spec = COLLECTORS_DIR / "spec.yaml"
    yamls = sorted([f.stem for f in COLLECTORS_DIR.glob("*.yaml") if f.stem != "spec"])

    lines = ["OS: Generic", "Artifacts:"]
    for name in yamls:
        lines.append(f"  MacOS.Collection.{name}: {{}}")

    # Output to /tmp — always writable, even with sudo
    output_dir = "/tmp"
    lines.extend([
        "Target: ZIP",
        "EncryptionScheme: None",
        "EncryptionArgs:",
        '  public_key: ""',
        '  password: ""',
        "OptVerbose: true",
        "OptBanner: true",
        "OptPrompt: false",
        "OptAdmin: true",
        "OptTempdir: /tmp",
        "OptLevel: 5",
        "OptConcurrency: 2",
        "OptFormat: jsonl",
        f"OptOutputDirectory: {output_dir}",
        "OptFilenameTemplate: Collection-%Hostname%-%TIMESTAMP%",
        'OptCollectorFilename: ""',
        "OptCpuLimit: 0",
        "OptProgressTimeout: 1800",
        "OptTimeout: 0",
        "OptDeleteAtExit: false",
        "",
    ])

    spec.write_text("\n".join(lines))
    return spec


def _get_local_arch() -> str:
    """Return 'arm64' or 'amd64' for the current Mac."""
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return "amd64"


def _binary_arch(binary: Path) -> str:
    """Return 'arm64' or 'amd64' based on the binary filename."""
    return "arm64" if "arm64" in binary.name else "amd64"


def build_collector(arch: str | None = None, progress_cb=None) -> tuple[list[str], list[str]]:
    """Build offline collectors for each downloaded velociraptor binary.

    Auto-generates spec.yaml from YAML files in collectors/, then repacks
    each binary into a standalone collector. Builds the native architecture
    first, then attempts the other (requires Rosetta on Apple Silicon).

    Returns (built_paths, errors).
    """
    yamls = list(COLLECTORS_DIR.glob("*.yaml"))
    artifact_yamls = [y for y in yamls if y.stem != "spec"]
    if not artifact_yamls:
        return [], ["No YAML artifacts found in collectors/"]

    if progress_cb:
        progress_cb(f"Generating spec.yaml from {len(artifact_yamls)} artifacts...")
    spec = _generate_spec()

    binaries = get_velo_binaries()
    if not binaries:
        return [], ["No velociraptor binaries found — click 'Download Velociraptor' first"]

    # Filter to requested arch if specified
    if arch:
        binaries = [b for b in binaries if _binary_arch(b) == arch]
        if not binaries:
            return [], [f"No {arch} binary found — download it first"]

    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    local_arch = _get_local_arch()

    built = []
    errors = []

    for binary in binaries:
        arch = _binary_arch(binary)
        is_native = arch == local_arch
        output = BUILD_DIR / f"Collector-darwin-{arch}"

        if progress_cb:
            label = f"{arch} (native)" if is_native else f"{arch} (cross-arch)"
            progress_cb(f"Building collector for {label}...")

        try:
            result = subprocess.run(
                [
                    str(binary),
                    "--definitions", str(COLLECTORS_DIR),
                    "collector", str(spec),
                ],
                capture_output=True, text=True, timeout=120,
            )

            if result.returncode != 0:
                stderr_lines = result.stderr.strip().splitlines()
                error_lines = [l for l in stderr_lines if "[ERROR]" in l or "error:" in l.lower()]
                err_msg = error_lines[-1] if error_lines else (stderr_lines[-1] if stderr_lines else f"exit {result.returncode}")
                err_msg = err_msg[:200]
                if "bad CPU type" in result.stderr.lower() or "bad cpu" in result.stderr.lower():
                    if _binary_arch(binary) == "amd64":
                        errors.append(
                            f"{_binary_arch(binary)}: Cannot run Intel binary on this Mac. "
                            "Install Rosetta (softwareupdate --install-rosetta) to build Intel collectors."
                        )
                    else:
                        errors.append(f"{_binary_arch(binary)}: Cannot run ARM binary on Intel Mac.")
                else:
                    errors.append(f"{_binary_arch(binary)}: {err_msg}")
            else:
                # Parse JSON stdout to find the output path
                collector_path = None
                try:
                    # stdout has JSON with the Repacked info
                    stdout = result.stdout.strip()
                    if stdout:
                        data = json.loads(stdout)
                        if isinstance(data, list) and data:
                            repacked = data[0].get("Repacked", {})
                            collector_path = repacked.get("Path")
                except Exception:
                    pass

                if collector_path and Path(collector_path).exists():
                    Path(collector_path).chmod(0o755)
                    shutil.move(collector_path, str(output))
                    built.append(str(output))
                else:
                    # Fallback: search common locations
                    for search in [
                        Path.home() / "gui_datastore",
                        Path("/var/folders"),
                    ]:
                        found = list(search.rglob("Collector_*")) if search.exists() else []
                        if found:
                            src = max(found, key=lambda f: f.stat().st_mtime)
                            src.chmod(0o755)
                            shutil.move(str(src), str(output))
                            built.append(str(output))
                            break
                    else:
                        errors.append(f"{_binary_arch(binary)}: Build ran but collector file not found")

        except OSError as e:
            if "bad CPU type" in str(e).lower() or e.errno == 86:
                if _binary_arch(binary) == "amd64":
                    errors.append(
                        f"{_binary_arch(binary)}: Cannot run Intel binary on this Mac. "
                        "Install Rosetta: softwareupdate --install-rosetta"
                    )
                else:
                    errors.append(f"{_binary_arch(binary)}: Cannot run ARM binary on Intel Mac.")
            else:
                errors.append(f"{_binary_arch(binary)}: {e}")
        except Exception as e:
            errors.append(f"{_binary_arch(binary)}: {e}")

    return built, errors


def get_collector_binary() -> str | None:
    """Return the path to the built collector matching this Mac's arch."""
    local = _get_local_arch()
    collector = BUILD_DIR / f"Collector-darwin-{local}"
    if collector.exists():
        return str(collector)
    # Fall back to any available collector
    for f in BUILD_DIR.glob("Collector-darwin-*"):
        return str(f)
    return None


def get_run_command() -> tuple[str | None, str | None]:
    """Return (command, error) for running the collector with sudo."""
    collector = get_collector_binary()
    if not collector:
        return None, "No collector built yet — click 'Build Intel' or 'Build Apple Silicon' first"
    COLLECTED_DIR.mkdir(parents=True, exist_ok=True)
    return collector, None

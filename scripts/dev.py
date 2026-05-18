#!/usr/bin/env python3
"""
Developer script for rjwt-py.

Usage:
    python3 scripts/dev.py <command> [options]

Single-step commands:
    stubs         Generate type stubs
    build         Build extension module
    check-stubs   Type-check example with mypy
    example       Run the example script
    docs          Build Sphinx documentation
    wheel         Build a distribution wheel
    check-wheel   Install wheel in a clean venv and verify it
    serve-docs    Serve built docs via http.server
    clean         Remove all generated artifacts (venvs, docs, wheels)

Multi-step workflows (support --skip / --only):
    ci            PR check pipeline: stubs, build, check-stubs, example, docs
    release       Release pipeline:  stubs, build, wheel, check-wheel
    all           Full pipeline:     all steps in order

Options:
    --release          Use release build profile (build / wheel / check-wheel)
    --skip STEP        Exclude a step from a workflow (repeatable)
    --only STEP        Run only this step from a workflow (repeatable)
    --port PORT        Port for serve-docs (default: 8000)
    --build            Build docs before serving (serve-docs only)
"""

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT    = Path(__file__).resolve().parent.parent
RJWT_PY_DIR  = REPO_ROOT / "rjwt-py"
EXAMPLES_DIR = REPO_ROOT / "examples"
TARGET_DIR   = REPO_ROOT / "target"
DOCS_OUT     = TARGET_DIR / "docs"
WHEELS_DIR   = TARGET_DIR / "wheels"

LOCAL_UV   = TARGET_DIR / "bin" / "uv"
BUILD_VENV = TARGET_DIR / "build_venv"
CHECK_VENV = TARGET_DIR / "check_venv"

_UV_PROJECT_ENVIRONMENT = "UV_PROJECT_ENVIRONMENT"

# ── Runtime state (populated in main() before any action is called) ───────────


@dataclass
class _State:
    uv:      str            = ""
    release: bool           = False
    env:     dict[str, str] = field(default_factory=dict)


_state = _State()

# ── GitHub Actions annotations ────────────────────────────────────────────────

_IN_CI = os.environ.get("CI") == "true"


def _group(name: str) -> None:
    if _IN_CI:
        print(f"::group::{name}", flush=True)


def _endgroup() -> None:
    if _IN_CI:
        print("::endgroup::", flush=True)


def _error(msg: str) -> None:
    if _IN_CI:
        print(f"::error::{msg}", flush=True)
    else:
        print(f"Error: {msg}", file=sys.stderr)


def _write_summary(results: list[tuple[str, bool]]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("## rjwt-py build\n\n")
        f.write("| Step | Result |\n|------|--------|\n")
        for name, ok in results:
            f.write(f"| `{name}` | {'✅' if ok else '❌'} |\n")


# ── Layer 1: uv primitives ────────────────────────────────────────────────────

def ensure_uv() -> None:
    if uv := shutil.which("uv"):
        _state.uv = uv
        return
    if LOCAL_UV.exists():
        _state.uv = str(LOCAL_UV)
        return
    print("Installing uv via cargo into target/bin/ ...")
    subprocess.run(
        ["cargo", "install", "uv", "--root", str(TARGET_DIR)],
        check=True,
    )
    _state.uv = str(LOCAL_UV)


def setup_build_venv() -> None:
    BUILD_VENV.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env[_UV_PROJECT_ENVIRONMENT] = str(BUILD_VENV)
    subprocess.run(
        [_state.uv, "sync", "--group", "build", "--group", "docs"],
        check=True,
        env=env,
        cwd=str(RJWT_PY_DIR),
    )


def init_env() -> None:
    _state.env = os.environ.copy()
    _state.env[_UV_PROJECT_ENVIRONMENT] = str(BUILD_VENV)
    _state.env["VIRTUAL_ENV"] = str(BUILD_VENV)
    _state.env["PATH"] = os.pathsep.join([
        str(_venv_bin(BUILD_VENV)),
        str(LOCAL_UV.parent),
        _state.env.get("PATH", ""),
    ])
    if sys.platform.startswith("darwin"):
        existing = _state.env.get("RUSTFLAGS", "")
        _state.env["RUSTFLAGS"] = (
            existing + " -C link-arg=-undefined -C link-arg=dynamic_lookup"
        ).strip()


def _venv_bin(venv: Path) -> Path:
    return venv / ("Scripts" if sys.platform == "win32" else "bin")


def _venv_python(venv: Path) -> str:
    if sys.platform == "win32":
        return str(venv / "Scripts" / "python.exe")
    return str(venv / "bin" / "python")



# ── Layer 2: actions ──────────────────────────────────────────────────────────

def _uv_run(*args: str) -> None:
    subprocess.run(
        [_state.uv, "run", *args],
        check=True,
        env=_state.env,
        cwd=str(RJWT_PY_DIR),
    )


def build_stubs() -> None:
    _uv_run("cargo", "run", "--bin", "stub_gen")


def build_module() -> None:
    _uv_run("maturin", "develop", *(["--release"] if _state.release else []))


def check_stubs() -> None:
    _uv_run("mypy", str(EXAMPLES_DIR / "example.py"))


def run_example() -> None:
    _uv_run("python", str(EXAMPLES_DIR / "example.py"))


def build_docs() -> None:
    DOCS_OUT.mkdir(parents=True, exist_ok=True)
    _uv_run("sphinx-build", "-W", "-b", "html",
            str(RJWT_PY_DIR / "docs"), str(DOCS_OUT))


def build_wheel() -> None:
    stub = RJWT_PY_DIR / "rjwt.pyi"
    if not stub.exists():
        raise RuntimeError(f"Stubs not found at {stub}. Run 'stubs' first.")
    WHEELS_DIR.mkdir(parents=True, exist_ok=True)
    _uv_run("maturin", "build", "--out", str(WHEELS_DIR),
            *(["--release"] if _state.release else []))


def check_wheel() -> None:
    wheels = sorted(WHEELS_DIR.glob("*.whl"), key=lambda p: p.stat().st_mtime)
    if not wheels:
        raise RuntimeError(
            f"No wheel found in {WHEELS_DIR}. Run the 'wheel' step first."
        )
    wheel = wheels[-1]
    print(f"Checking wheel: {wheel.name}")

    shutil.rmtree(CHECK_VENV, ignore_errors=True)
    try:
        subprocess.run([_state.uv, "venv", str(CHECK_VENV)], check=True)

        python = _venv_python(CHECK_VENV)
        subprocess.run(
            [_state.uv, "pip", "install", str(wheel), "--python", python],
            check=True,
        )

        _uv_run("mypy", "--python-executable", python, str(EXAMPLES_DIR / "example.py"))
        subprocess.run([python, str(EXAMPLES_DIR / "example.py")], check=True)
    finally:
        shutil.rmtree(CHECK_VENV, ignore_errors=True)


def clean() -> None:
    for path in (BUILD_VENV, CHECK_VENV, DOCS_OUT, WHEELS_DIR):
        print(f"Removing {path}")
        shutil.rmtree(path, ignore_errors=True)
    for artifact in (RJWT_PY_DIR / "rjwt.pyi", RJWT_PY_DIR / "uv.lock"):
        if artifact.exists():
            print(f"Removing {artifact}")
            artifact.unlink()


# ── Step registry and workflow definitions ────────────────────────────────────

STEPS: dict[str, str] = {
    "stubs":       "Generate type stubs",
    "build":       "Build extension module",
    "check-stubs": "Type-check example with mypy",
    "example":     "Run example script",
    "docs":        "Build Sphinx documentation",
    "wheel":       "Build distribution wheel",
    "check-wheel": "Install wheel in clean venv and verify",
}

WORKFLOWS: dict[str, list[str]] = {
    "ci":      ["stubs", "build", "check-stubs", "example", "docs"],
    "release": ["stubs", "build", "wheel", "check-wheel"],
    "all":     ["stubs", "build", "check-stubs", "example", "docs", "wheel", "check-wheel"],
}

_STEP_FNS: dict[str, Callable[[], None]] = {
    "stubs":       build_stubs,
    "build":       build_module,
    "check-stubs": check_stubs,
    "example":     run_example,
    "docs":        build_docs,
    "wheel":       build_wheel,
    "check-wheel": check_wheel,
}


def _dispatch_step(name: str) -> None:
    fn = _STEP_FNS.get(name)
    if fn is None:
        raise ValueError(f"Unknown step: {name!r}")
    fn()


def _resolve_steps(workflow: str, skip: list[str], only: list[str]) -> list[str]:
    valid = set(STEPS)
    for s in skip + only:
        if s not in valid:
            print(
                f"Unknown step {s!r}. Valid steps: {', '.join(sorted(valid))}",
                file=sys.stderr,
            )
            sys.exit(1)

    base = WORKFLOWS[workflow]
    if only:
        only_set = set(only)
        return [s for s in base if s in only_set]
    return [s for s in base if s not in set(skip)]


def _run_workflow(steps: list[str]) -> bool:
    results: list[tuple[str, bool]] = []
    all_ok = True

    for name in steps:
        print(f"\n── {name} ──")
        _group(name)
        try:
            _dispatch_step(name)
            results.append((name, True))
        except (subprocess.CalledProcessError, RuntimeError) as e:
            _error(f"{name} failed: {e}")
            results.append((name, False))
            all_ok = False
            break
        finally:
            _endgroup()

    _write_summary(results)

    print("\n── Summary ──")
    for name, ok in results:
        print(f"  {'✓' if ok else '✗'} {name}")

    return all_ok


# ── Layer 3: CLI ──────────────────────────────────────────────────────────────

def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

    all_commands = list(STEPS) + list(WORKFLOWS) + ["serve-docs", "clean"]

    parser = argparse.ArgumentParser(
        description="Developer script for rjwt-py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "command",
        choices=all_commands,
        metavar="COMMAND",
        help=f"Step or workflow to run. One of: {', '.join(all_commands)}",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="Use release build profile (build, wheel, check-wheel)",
    )
    parser.add_argument(
        "--skip",
        metavar="STEP",
        action="append",
        default=[],
        help="Exclude a step from a workflow (repeatable)",
    )
    parser.add_argument(
        "--only",
        metavar="STEP",
        action="append",
        default=[],
        help="Run only this step from a workflow (repeatable)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for serve-docs (default: 8000)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build docs before serving (serve-docs only)",
    )
    args = parser.parse_args()

    # ── clean (needs no uv or venv setup) ────────────────────────────────────
    if args.command == "clean":
        clean()
        return

    ensure_uv()
    _state.release = args.release

    # ── serve-docs (blocking; not part of any workflow) ───────────────────────
    if args.command == "serve-docs":
        if args.build:
            setup_build_venv()
            init_env()
            build_docs()
        if not DOCS_OUT.exists():
            print(
                f"Docs not found at {DOCS_OUT}. Run 'docs' first or pass --build.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Serving docs at http://localhost:{args.port}/  (Ctrl-C to stop)")
        subprocess.run(
            [sys.executable, "-m", "http.server", str(args.port),
             "--directory", str(DOCS_OUT)],
        )
        return

    setup_build_venv()
    init_env()

    # ── single-step command ───────────────────────────────────────────────────
    if args.command in STEPS:
        _group(args.command)
        try:
            _dispatch_step(args.command)
            print(f"✓ {args.command}")
        except (subprocess.CalledProcessError, RuntimeError) as e:
            _error(str(e))
            sys.exit(1)
        finally:
            _endgroup()
        return

    # ── multi-step workflow ───────────────────────────────────────────────────
    steps = _resolve_steps(args.command, args.skip, args.only)
    if not steps:
        print("No steps to run after applying --skip / --only.", file=sys.stderr)
        sys.exit(1)

    ok = _run_workflow(steps)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

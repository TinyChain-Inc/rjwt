#!/usr/bin/env python3
"""
Build and run the rjwt-py example.

Usage:
    python3 build.py           # debug build
    python3 build.py --release # release build
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RJWT_PY_DIR = REPO_ROOT / "rjwt-py"
EXAMPLE_SCRIPT = Path(__file__).resolve().parent / "example.py"


def find_uv() -> str | None:
    if uv := shutil.which("uv"):
        return uv
    for candidate in [
        Path.home() / ".cargo/bin/uv",
        Path.home() / ".local/bin/uv",
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def create_venv(venv_path: Path, uv: str | None) -> None:
    if venv_path.exists():
        print(f"venv exists: {venv_path}")
        return
    venv_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Creating venv: {venv_path}")
    if uv:
        subprocess.run([uv, "venv", str(venv_path)], check=True)
    else:
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)


def ensure_maturin(venv_path: Path, uv: str | None) -> str:
    maturin = venv_path / "bin" / "maturin"
    if maturin.exists():
        print("maturin already installed")
        return str(maturin)
    print("Installing maturin...")
    python = str(venv_path / "bin" / "python")
    if uv:
        subprocess.run([uv, "pip", "install", "maturin", "--python", python], check=True)
    else:
        subprocess.run([python, "-m", "pip", "install", "maturin"], check=True)
    return str(maturin)


def build_extension(maturin: str, venv_path: Path, release: bool) -> None:
    import os
    cmd = [maturin, "develop"]
    if release:
        cmd.append("--release")
    print(f"Building extension: {' '.join(cmd)}")
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_path)
    env["PATH"] = str(venv_path / "bin") + ":" + env.get("PATH", "")
    subprocess.run(cmd, check=True, cwd=str(RJWT_PY_DIR), env=env)


def run_example(venv_path: Path) -> None:
    python = str(venv_path / "bin" / "python")
    print(f"Running: {EXAMPLE_SCRIPT}\n")
    subprocess.run([python, str(EXAMPLE_SCRIPT)], check=True)


def clean_venv(venv_path: Path) -> None:
    print(f"Cleaning venv: {venv_path}")
    shutil.rmtree(venv_path, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and run the rjwt-py example.")
    parser.add_argument("--release", action="store_true", help="Use release build profile")
    args = parser.parse_args()

    profile = "release" if args.release else "debug"
    venv_path = REPO_ROOT / "target" / profile / "venv"
    uv = find_uv()

    success = False
    try:
        create_venv(venv_path, uv)
        maturin = ensure_maturin(venv_path, uv)
        build_extension(maturin, venv_path, args.release)
        run_example(venv_path)
        success = True
    except subprocess.CalledProcessError as e:
        print(f"\nError: {e}", file=sys.stderr)
    finally:
        clean_venv(venv_path)

    if success:
        print("\nStatus: SUCCESS")
        sys.exit(0)
    else:
        print("\nStatus: FAILURE", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

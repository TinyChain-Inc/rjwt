#!/usr/bin/env python3
"""
Build and run the rjwt-py example.

Usage:
    python3 build.py           # debug build
    python3 build.py --release # release build
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RJWT_PY_DIR = REPO_ROOT / "rjwt-py"
EXAMPLES_DIR = REPO_ROOT / "examples"
TARGET_DIR = REPO_ROOT / "target"

# uv is installed here when not found globally
LOCAL_UV = TARGET_DIR / "bin" / "uv"
UV_ENV_VAR_FOR_VENV = "UV_PROJECT_ENVIRONMENT"

BUILD_VENV = TARGET_DIR / "build_venv"
TEST_VENV = TARGET_DIR / "test_venv"


def ensure_uv() -> str:
    if uv := shutil.which("uv"):
        return uv

    if LOCAL_UV.exists():
        return str(LOCAL_UV)
    
    print("Installing uv locally via cargo into target/bin/...")
    subprocess.run(
        ["cargo", "install", "uv", "--root", str(REPO_ROOT / "target")],
        check=True,
    )
    return str(LOCAL_UV)


def create_custom_venv(venv_path: Path, uv: str) -> None:
    if venv_path.exists():
        print(f"venv exists: {venv_path}")
        return
    venv_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Creating venv: {venv_path}")
    subprocess.run([uv, "venv", str(venv_path)], check=True)


def create_venv(uv: str) -> None:
    ensure_path(BUILD_VENV)
    env = os.environ.copy()
    env[UV_ENV_VAR_FOR_VENV] = str(BUILD_VENV)
    subprocess.run([uv, "sync", "--group", "build", "--group", "docs"], check=True, env=env, cwd=str(RJWT_PY_DIR))


def ensure_maturin(venv_path: Path, uv: str) -> str:
    maturin = venv_path / "bin" / "maturin"
    if maturin.exists():
        print("maturin already installed")
        return str(maturin)
    print("Installing maturin...")
    python = str(venv_path / "bin" / "python")
    subprocess.run([uv, "pip", "install", "maturin", "--python", python], check=True)
    return str(maturin)


def build_extension(maturin: str, venv_path: Path, release: bool) -> None:
    cmd = [maturin, "develop"]
    if release:
        cmd.append("--release")
    print(f"Building extension: {' '.join(cmd)}")
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_path)
    env["PATH"] = ":".join([
        str(venv_path / "bin"),
        str(LOCAL_UV.parent),
        env.get("PATH", ""),
    ])
    subprocess.run(cmd, check=True, cwd=str(RJWT_PY_DIR), env=env)


def build_wheel(maturin: str, release: bool) -> None: 
    cmd = [maturin, "build"]
    if release:
        cmd.append("--release")
    print(f"Building wheel: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def clean_venv(venv_path: Path) -> None:
    print(f"Cleaning venv: {venv_path}")
    shutil.rmtree(venv_path, ignore_errors=True)


def hard_reset_venv(uv: str):
    clean_venv(BUILD_VENV)
    create_venv(uv)


def ensure_path(path: Path) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
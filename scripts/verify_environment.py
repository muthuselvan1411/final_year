#!/usr/bin/env python3
"""
Environment Verification Script for RansomShield Reproducibility.
Records OS, Python version, hardware specs, git commit, and package versions.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def get_git_commit(repo_root: Path) -> str:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return commit
    except Exception:
        return "UNKNOWN_OR_NOT_A_GIT_REPO"


def get_system_specs() -> Dict[str, Any]:
    specs: Dict[str, Any] = {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }
    return specs


def check_packages(required_packages: list[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for pkg in required_packages:
        try:
            mod = importlib.import_module(pkg)
            version = getattr(mod, "__version__", "installed_unknown_version")
            results[pkg] = {"installed": True, "version": str(version)}
        except ImportError:
            results[pkg] = {"installed": False, "version": None}
    return results


def verify_environment(output_json: Path | None = None) -> Dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent
    specs = get_system_specs()
    specs["git_commit"] = get_git_commit(repo_root)
    specs["timestamp_utc"] = datetime.now(timezone.utc).isoformat()

    core_packages = [
        "numpy",
        "pandas",
        "scipy",
        "sklearn",
        "yaml",
        "pydantic",
        "pytest",
    ]
    pkg_status = check_packages(core_packages)
    specs["packages"] = pkg_status

    missing = [pkg for pkg, data in pkg_status.items() if not data["installed"]]
    specs["all_dependencies_met"] = len(missing) == 0
    specs["missing_packages"] = missing

    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(specs, f, indent=2)

    return specs


def main() -> None:
    print("=" * 60)
    print("RansomShield Environment Verification")
    print("=" * 60)
    specs = verify_environment()
    print(f"Platform:           {specs['platform']}")
    print(f"Python Version:     {specs['python_version']}")
    print(f"Git Commit:         {specs['git_commit']}")
    print(f"CPU Count:          {specs['cpu_count']}")
    print("-" * 60)
    print("Dependency Status:")
    for pkg, info in specs["packages"].items():
        status = f"v{info['version']}" if info["installed"] else "MISSING"
        print(f"  - {pkg:<15}: {status}")
    print("-" * 60)
    if specs["all_dependencies_met"]:
        print("[PASS] All core dependencies are installed.")
        sys.exit(0)
    else:
        print(f"[FAIL] Missing packages: {specs['missing_packages']}")
        print("Please install via: pip install -r requirements-lock.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test Runner for RansomShield Unit Tests.
Works with standard library or pytest.
"""

from __future__ import annotations

import importlib
import inspect
import sys
import traceback
from pathlib import Path

# Add src and repo root to path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "src"))
sys.path.insert(0, str(repo_root))


def run_all_tests() -> bool:
    test_files = [
        "tests.test_config_validation",
        "tests.test_manifest",
        "tests.test_decision_contract",
        "tests.test_inspect_dataset",
        "tests.test_data_validation",
        "tests.test_splits",
        "tests.test_policy",
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0

    print("=" * 60)
    print("RansomShield Unit Test Execution")
    print("=" * 60)

    for mod_name in test_files:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            print(f"[FAIL] Could not import {mod_name}: {e}")
            traceback.print_exc()
            return False

        print(f"\nRunning tests in {mod_name}:")
        for attr_name in dir(mod):
            if attr_name.startswith("test_"):
                fn = getattr(mod, attr_name)
                if inspect.isfunction(fn):
                    total_tests += 1
                    try:
                        # Call function with tmp_path if needed
                        sig = inspect.signature(fn)
                        if "tmp_path" in sig.parameters:
                            import tempfile
                            with tempfile.TemporaryDirectory() as td:
                                fn(Path(td))
                        else:
                            fn()
                        print(f"  [PASS] {attr_name}")
                        passed_tests += 1
                    except Exception as exc:
                        print(f"  [FAIL] {attr_name}: {exc}")
                        traceback.print_exc()
                        failed_tests += 1

    print("\n" + "=" * 60)
    print(f"Test Summary: {passed_tests} PASSED, {failed_tests} FAILED (Total: {total_tests})")
    print("=" * 60)
    return failed_tests == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

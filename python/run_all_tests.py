"""
run_all_tests.py — Zero Trust IoT Python Migration: Test Runner

Runs each example script in an isolated subprocess using the ns-3 environment,
reporting PASS/FAIL for each test scenario.
"""

import sys
import os
import subprocess

NS3_DIR = os.path.expanduser("~/Desktop/ns-allinone-3.46.1/ns-3.46.1")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXAMPLES = [
    ("micro-segmentation-test",        "examples/micro-segmentation-test.py"),
    ("trust-scorer-test",              "examples/trust-scorer-test.py"),
    ("context-drift-test",             "examples/context-drift-test.py"),
    ("unauthorized-access-attack",     "examples/unauthorized-access/unauthorized-access-attack.py"),
    ("unauthorized-access-mitigation", "examples/unauthorized-access/unauthorized-access-mitigation.py"),
    ("mitm-attack",                    "examples/mitm/mitm-attack.py"),
    ("mitm-mitigation",                "examples/mitm/mitm-mitigation.py"),
    ("spoofing-attack",                "examples/spoofing/spoofing-attack.py"),
    ("spoofing-mitigation",            "examples/spoofing/spoofing-mitigation.py"),
]

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def run_example(name: str, rel_path: str) -> bool:
    print(f"\n{'='*60}")
    print(f"  Running: {name}")
    print(f"{'='*60}")
    full_path = os.path.join(BASE_DIR, rel_path)
    cmd = ["./ns3", "run", full_path]
    try:
        proc = subprocess.run(cmd, cwd=NS3_DIR, text=True, capture_output=True)
        if proc.stdout:
            print(proc.stdout.strip())
        if proc.stderr:
            print(proc.stderr.strip(), file=sys.stderr)
        return proc.returncode == 0
    except Exception as e:
        print(f"Error executing {name}: {e}")
        return False


def main() -> None:
    print("=" * 60)
    print("Zero Trust IoT — Python NS-3 Test Suite Runner")
    print("=" * 60)

    results = []
    for name, rel_path in EXAMPLES:
        ok = run_example(name, rel_path)
        results.append((name, ok))

    print(f"\n{'='*60}")
    print("  TEST SUITE SUMMARY")
    print(f"{'='*60}")
    for name, ok in results:
        status = PASS if ok else FAIL
        print(f"  [{status}] {name}")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n  Result: {passed}/{total} examples passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()

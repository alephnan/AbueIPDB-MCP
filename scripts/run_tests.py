#!/usr/bin/env python3
"""
Test runner script for MCP AbuseIPDB server.

This script provides an easy way to run different types of tests locally.
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path


def run_command(cmd, description="", check=True):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"Running: {description or ' '.join(cmd)}")
    print(f"{'='*60}")

    try:
        result = subprocess.run(cmd, check=check, cwd=Path(__file__).parent.parent)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}")
        return False


def run_unit_tests(coverage=False, verbose=False):
    """Run unit tests."""
    cmd = ["python", "-m", "pytest", "tests/"]

    # Exclude slow tests by default
    cmd.extend([
        "--ignore=tests/test_docker.py",
        "--ignore=tests/test_integration.py"
    ])

    if coverage:
        cmd.extend([
            "--cov=mcp_abuseipdb",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov"
        ])

    if verbose:
        cmd.append("-v")

    return run_command(cmd, "Unit Tests")


def run_integration_tests(verbose=False):
    """Run integration tests."""
    cmd = ["python", "-m", "pytest", "tests/test_integration.py"]

    if verbose:
        cmd.append("-v")

    return run_command(cmd, "Integration Tests")


def run_docker_tests(verbose=False):
    """Run Docker tests."""
    cmd = ["python", "-m", "pytest", "tests/test_docker.py"]

    if verbose:
        cmd.append("-v")

    return run_command(cmd, "Docker Tests")




def run_all_tests(coverage=False, verbose=False):
    """Run all tests."""
    print("Running complete test suite...")

    results = {
        "Unit Tests": run_unit_tests(coverage=coverage, verbose=verbose),
        "Integration Tests": run_integration_tests(verbose=verbose),
    }

    # Docker tests are optional (require Docker)
    docker_result = run_docker_tests(verbose=verbose)
    if docker_result:
        results["Docker Tests"] = True
    else:
        print("\nDocker tests skipped (Docker not available or image not built)")

    # Print summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")

    all_passed = True
    for test_type, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"{test_type:<20}: {status}")
        if not passed:
            all_passed = False

    print(f"{'='*60}")
    overall_status = "ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED"
    print(f"Overall Result: {overall_status}")
    print(f"{'='*60}")

    return all_passed


def setup_environment():
    """Set up test environment."""
    env_file = Path(__file__).parent.parent / ".env.test"
    if env_file.exists():
        print(f"Loading test environment from {env_file}")
        # Load environment variables from .env.test
        with open(env_file) as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(
        description="Test runner for MCP AbuseIPDB server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/run_tests.py --all                    # Run all tests
  python scripts/run_tests.py --unit --coverage        # Unit tests with coverage
  python scripts/run_tests.py --integration            # Integration tests only
  python scripts/run_tests.py --docker                 # Docker tests only
        """
    )

    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--docker", action="store_true", help="Run Docker tests")
    parser.add_argument("--coverage", action="store_true", help="Include coverage reporting")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Set up environment
    setup_environment()

    # If no specific tests selected, default to unit tests
    if not any([args.all, args.unit, args.integration, args.docker]):
        args.unit = True

    success = True

    if args.all:
        success = run_all_tests(coverage=args.coverage, verbose=args.verbose)
    else:
        if args.unit:
            success &= run_unit_tests(coverage=args.coverage, verbose=args.verbose)

        if args.integration:
            success &= run_integration_tests(verbose=args.verbose)

        if args.docker:
            success &= run_docker_tests(verbose=args.verbose)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
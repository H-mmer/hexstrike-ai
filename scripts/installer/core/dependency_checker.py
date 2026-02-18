#!/usr/bin/env python3
"""Dependency Checker for HexStrike AI Installer

Validates system requirements before installation:
- Python version >= 3.8
- pip availability
- git availability
- Disk space
- Internet connectivity
"""

import sys
import shutil
import socket
from dataclasses import dataclass
from typing import Dict
from pathlib import Path


class DependencyError(Exception):
    """Raised when a required dependency is missing"""
    pass


@dataclass
class DependencyCheckResult:
    """Result of a dependency check"""
    name: str
    passed: bool
    message: str = ""

    def __str__(self) -> str:
        status = "✓" if self.passed else "✗"
        return f"{status} {self.name}: {self.message}"


class DependencyChecker:
    """Check system dependencies before installation"""

    MIN_PYTHON_MAJOR = 3
    MIN_PYTHON_MINOR = 8

    def check_python_version(self) -> DependencyCheckResult:
        """Check if Python version is >= 3.8"""
        major = sys.version_info.major
        minor = sys.version_info.minor

        if major < self.MIN_PYTHON_MAJOR or (
            major == self.MIN_PYTHON_MAJOR and minor < self.MIN_PYTHON_MINOR
        ):
            return DependencyCheckResult(
                name="Python Version",
                passed=False,
                message=f"Python {self.MIN_PYTHON_MAJOR}.{self.MIN_PYTHON_MINOR}+ required, found {major}.{minor}"
            )

        return DependencyCheckResult(
            name="Python Version",
            passed=True,
            message=f"Python {major}.{minor}"
        )

    def check_pip(self) -> DependencyCheckResult:
        """Check if pip is installed"""
        pip_path = shutil.which('pip3') or shutil.which('pip')

        if not pip_path:
            return DependencyCheckResult(
                name="pip",
                passed=False,
                message="pip not found - install with: sudo apt install python3-pip"
            )

        return DependencyCheckResult(
            name="pip",
            passed=True,
            message=f"Found at {pip_path}"
        )

    def check_git(self) -> DependencyCheckResult:
        """Check if git is installed"""
        git_path = shutil.which('git')

        if not git_path:
            return DependencyCheckResult(
                name="git",
                passed=False,
                message="git not found - install with: sudo apt install git"
            )

        return DependencyCheckResult(
            name="git",
            passed=True,
            message=f"Found at {git_path}"
        )

    def check_disk_space(self, required_gb: int = 5) -> DependencyCheckResult:
        """Check available disk space

        Args:
            required_gb: Required disk space in GB (default: 5GB)
        """
        try:
            usage = shutil.disk_usage('/')
            available_gb = usage.free / (1024 ** 3)

            if available_gb < required_gb:
                return DependencyCheckResult(
                    name="Disk Space",
                    passed=False,
                    message=f"Insufficient disk space: {available_gb:.1f}GB available, {required_gb}GB required"
                )

            return DependencyCheckResult(
                name="Disk Space",
                passed=True,
                message=f"{available_gb:.1f}GB available"
            )

        except Exception as e:
            return DependencyCheckResult(
                name="Disk Space",
                passed=False,
                message=f"Could not check disk space: {e}"
            )

    def check_internet(self) -> DependencyCheckResult:
        """Check internet connectivity"""
        try:
            # Try to connect to Google DNS
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return DependencyCheckResult(
                name="Internet",
                passed=True,
                message="Connected"
            )
        except OSError:
            return DependencyCheckResult(
                name="Internet",
                passed=False,
                message="No internet connection detected"
            )

    def check_all(self, raise_on_failure: bool = False) -> Dict[str, DependencyCheckResult]:
        """Run all dependency checks

        Args:
            raise_on_failure: If True, raise DependencyError on first failure

        Returns:
            Dictionary mapping check name to result

        Raises:
            DependencyError: If raise_on_failure=True and any check fails
        """
        results = {
            'python_version': self.check_python_version(),
            'pip': self.check_pip(),
            'git': self.check_git(),
            'disk_space': self.check_disk_space(),
            'internet': self.check_internet()
        }

        if raise_on_failure:
            failed = [r for r in results.values() if not r.passed]
            if failed:
                error_messages = [f"  • {r.name}: {r.message}" for r in failed]
                raise DependencyError(
                    f"Dependency checks failed:\n" + "\n".join(error_messages)
                )

        return results


def main():
    """Run dependency checks and print results"""
    checker = DependencyChecker()
    results = checker.check_all()

    print("\nDependency Check Results:")
    print("-" * 50)

    all_passed = True
    for result in results.values():
        print(f"  {result}")
        if not result.passed:
            all_passed = False

    print("-" * 50)

    if all_passed:
        print("\n✓ All dependency checks passed!")
        sys.exit(0)
    else:
        print("\n✗ Some dependency checks failed. Please resolve them before installing.")
        sys.exit(1)


if __name__ == '__main__':
    main()

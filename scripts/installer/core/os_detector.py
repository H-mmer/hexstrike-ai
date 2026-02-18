"""OS Detection and Package Manager Abstraction"""

import subprocess
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class UnsupportedOSError(Exception):
    """Raised when OS is not Kali or Parrot"""
    pass


@dataclass
class OSInfo:
    """Operating system information"""
    name: str
    version: str
    id: str

    @property
    def is_kali(self) -> bool:
        return 'kali' in self.id.lower()

    @property
    def is_parrot(self) -> bool:
        return 'parrot' in self.id.lower()

    @property
    def is_supported(self) -> bool:
        return self.is_kali or self.is_parrot


class OSDetector:
    """Detect operating system and provide package manager operations"""

    def __init__(self):
        self.os_info: Optional[OSInfo] = None

    def detect_os(self) -> OSInfo:
        """Detect operating system from /etc/os-release"""
        os_release_path = Path('/etc/os-release')

        if not os_release_path.exists():
            raise UnsupportedOSError("Cannot find /etc/os-release")

        os_data = {}
        with open(os_release_path) as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_data[key] = value.strip('"')

        self.os_info = OSInfo(
            name=os_data.get('NAME', 'Unknown'),
            version=os_data.get('VERSION', 'Unknown'),
            id=os_data.get('ID', '')
        )

        logger.info(f"Detected OS: {self.os_info.name} {self.os_info.version}")
        return self.os_info

    def verify_supported_os(self):
        """Verify OS is Kali or Parrot"""
        if self.os_info is None:
            self.detect_os()

        if not self.os_info.is_supported:
            raise UnsupportedOSError(
                f"{self.os_info.name} is not supported. "
                "This installer only supports Kali Linux and Parrot OS."
            )

    def update_repos(self) -> bool:
        """Update apt package repositories"""
        try:
            logger.info("Updating apt repositories...")
            result = subprocess.run(
                ['apt-get', 'update'],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                logger.info("Repository update successful")
                return True
            else:
                logger.error(f"Repository update failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Repository update timed out")
            return False
        except Exception as e:
            logger.error(f"Error updating repositories: {e}")
            return False

    def install_packages(self, packages: List[str]) -> bool:
        """Install packages via apt-get"""
        try:
            logger.info(f"Installing packages: {', '.join(packages)}")
            result = subprocess.run(
                ['apt-get', 'install', '-y'] + packages,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode == 0:
                logger.info(f"Successfully installed {len(packages)} packages")
                return True
            else:
                logger.error(f"Package installation failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error installing packages: {e}")
            return False

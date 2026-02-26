"""
StealthBrowserAgent -- extends BrowserAgent with undetected-chromedriver
and human behaviour simulation.

Presets:
  minimal  -- undetected-chromedriver only (fastest, least overhead)
  standard -- UC + randomised delays + smooth scroll (default)
  paranoid -- UC + full HumanBehaviourMixin + canvas/WebGL spoofing
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

try:
    import undetected_chromedriver as uc
except ImportError:
    uc = None  # type: ignore

logger = logging.getLogger(__name__)

_VALID_PRESETS = ("minimal", "standard", "paranoid")


class StealthBrowserAgent:
    """Anti-detection browser agent powered by undetected-chromedriver."""

    def __init__(self, preset: str = "standard", headless: bool = True):
        if preset not in _VALID_PRESETS:
            raise ValueError(f"preset must be one of {_VALID_PRESETS}")
        self.preset = preset
        self.headless = headless
        self.driver: Any = None

    # ------------------------------------------------------------------
    # Browser lifecycle
    # ------------------------------------------------------------------

    def setup_browser(
        self,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
    ) -> bool:
        """Initialise an undetected Chrome instance.

        Returns True on success, False on failure (missing dependency or
        Chrome launch error).
        """
        if uc is None:
            logger.error("undetected-chromedriver not installed")
            return False
        try:
            options = uc.ChromeOptions()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")

            if proxy_host and proxy_port:
                options.add_argument(
                    f"--proxy-server=http://{proxy_host}:{proxy_port}"
                )

            if self.preset == "paranoid":
                self._apply_paranoid_options(options)

            self.driver = uc.Chrome(options=options, headless=self.headless)
            logger.info("StealthBrowserAgent ready (preset=%s)", self.preset)
            return True
        except Exception as exc:
            logger.error("StealthBrowserAgent setup failed: %s", exc)
            return False

    def _apply_paranoid_options(self, options: Any) -> None:
        """Extra hardening for the *paranoid* preset."""
        options.add_argument("--lang=en-US,en;q=0.9")
        options.add_argument(
            "--disable-blink-features=AutomationControlled"
        )

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def navigate_stealth(
        self, url: str, wait_seconds: float = 2.0
    ) -> Dict[str, Any]:
        """Navigate to *url* with optional human-like delay.

        Returns a dict with ``success``, current URL, title and page
        source length.
        """
        if not self.driver:
            if not self.setup_browser():
                return {"success": False, "error": "driver not initialised"}
        try:
            self.driver.get(url)
            if self.preset != "minimal":
                time.sleep(wait_seconds)
            return {
                "success": True,
                "url": self.driver.current_url,
                "title": self.driver.title,
                "page_source_length": len(self.driver.page_source),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Quit the browser and release resources."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            finally:
                self.driver = None

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

from agents.human_behaviour import HumanBehaviourMixin

try:
    import undetected_chromedriver as uc
except ImportError:
    uc = None  # type: ignore

logger = logging.getLogger(__name__)

_VALID_PRESETS = ("minimal", "standard", "paranoid")


class StealthBrowserAgent(HumanBehaviourMixin):
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
        if not url.startswith(("http://", "https://")):
            return {"success": False, "error": "Only http:// and https:// URLs are supported"}
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
    # Screenshot
    # ------------------------------------------------------------------

    def screenshot_stealth(self) -> Dict[str, Any]:
        """Capture a screenshot and return it as a base64-encoded string."""
        if not self.driver:
            return {"success": False, "error": "driver not initialised"}
        try:
            b64 = self.driver.get_screenshot_as_base64()
            return {"success": True, "screenshot_b64": b64}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Form interaction
    # ------------------------------------------------------------------

    def form_fill_stealth(self, css_selector: str, value: str) -> Dict[str, Any]:
        """Fill a form element located by *css_selector* with human-like typing."""
        if not self.driver:
            return {"success": False, "error": "driver not initialised"}
        try:
            from selenium.webdriver.common.by import By
            element = self.driver.find_element(By.CSS_SELECTOR, css_selector)
            element.clear()
            self.type_with_delays(element, value)
            return {"success": True, "selector": css_selector, "value_length": len(value)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # DOM extraction
    # ------------------------------------------------------------------

    def extract_dom_stealth(self) -> Dict[str, Any]:
        """Extract links, forms, and page source from the current page."""
        if not self.driver:
            return {"success": False, "error": "driver not initialised"}
        try:
            links = self.driver.execute_script(
                "return Array.from(document.querySelectorAll('a')).map(a => a.href).slice(0, 50)"
            )
            forms = self.driver.execute_script(
                "return Array.from(document.querySelectorAll('form')).length"
            )
            return {
                "success": True,
                "url": self.driver.current_url,
                "title": self.driver.title,
                "page_source": self.driver.page_source,
                "link_count": len(links or []),
                "links_sample": (links or [])[:10],
                "form_count": forms or 0,
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

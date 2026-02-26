# agents/human_behaviour.py
"""HumanBehaviourMixin: randomised, human-like interactions for Selenium/UC drivers."""
from __future__ import annotations

import random
import time
from typing import Any

try:
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    ActionChains = None  # type: ignore


def _bezier_points(p0: tuple, p1: tuple, p2: tuple, n: int = 10) -> list:
    """Compute *n+1* points along a quadratic Bezier curve from *p0* to *p2*
    with control point *p1*."""
    points = []
    for i in range(n + 1):
        t = i / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        points.append((x, y))
    return points


class HumanBehaviourMixin:
    """Mixin that adds human-like browser interactions.

    Methods can be used standalone or mixed into any browser agent class
    (e.g. ``StealthBrowserAgent``).
    """

    def type_with_delays(
        self,
        element: Any,
        text: str,
        min_delay: float = 0.05,
        max_delay: float = 0.18,
    ) -> None:
        """Send *text* to *element* one character at a time with random delays."""
        for char in text:
            element.send_keys(char)
            time.sleep(random.uniform(min_delay, max_delay))

    def smooth_scroll(
        self,
        driver: Any,
        distance: int = 300,
        steps: int = 10,
        step_delay: float = 0.03,
    ) -> None:
        """Scroll the page by *distance* pixels in small incremental steps."""
        step_size = distance // steps
        for _ in range(steps):
            driver.execute_script(f"window.scrollBy(0, {step_size});")
            time.sleep(step_delay)

    def random_pause(self, min_s: float = 0.5, max_s: float = 2.0) -> None:
        """Sleep for a random duration between *min_s* and *max_s* seconds."""
        time.sleep(random.uniform(min_s, max_s))

    def bezier_mouse_move(
        self,
        driver: Any,
        dx: int = 100,
        dy: int = 50,
        steps: int = 10,
        step_delay: float = 0.02,
    ) -> None:
        """Move the mouse along a quadratic Bezier curve by *(dx, dy)*.

        Requires ``selenium`` to be installed; silently returns if
        ``ActionChains`` is unavailable.
        """
        if ActionChains is None:
            return
        cx = dx // 2 + random.randint(-20, 20)
        cy = dy // 4 + random.randint(-10, 10)
        points = _bezier_points((0, 0), (cx, cy), (dx, dy), n=steps)
        actions = ActionChains(driver)
        prev_x, prev_y = 0, 0
        for px, py in points[1:]:
            delta_x = int(px - prev_x)
            delta_y = int(py - prev_y)
            actions.move_by_offset(delta_x, delta_y)
            prev_x, prev_y = px, py
        actions.perform()
        time.sleep(step_delay)

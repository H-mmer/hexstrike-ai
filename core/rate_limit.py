# core/rate_limit.py
"""Rate limiting middleware via flask-limiter."""
import logging

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)


def register_rate_limiter(app):
    """Register rate limits on *app*."""
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["60/minute"],
        storage_uri="memory://",
    )

    # Stricter limit on arbitrary command execution
    cmd_key = "system.run_command"
    cmd_view = app.view_functions.get(cmd_key)
    if cmd_view is not None:
        app.view_functions[cmd_key] = limiter.limit("10/minute")(cmd_view)
    else:
        logger.warning("system.run_command endpoint not found — skipping rate limit")

    # Exempt health endpoint from default limits
    health_key = "system.health_check"
    health_view = app.view_functions.get(health_key)
    if health_view is not None:
        app.view_functions[health_key] = limiter.exempt(health_view)
    else:
        logger.warning("system.health_check endpoint not found — skipping exemption")

    logger.info("Rate limiter registered: 60/min default, 10/min for /api/command")
    return limiter

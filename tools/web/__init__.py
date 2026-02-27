# tools/web/__init__.py
"""Web application security tools."""
try:
    from tools.web.auth_testing import *
except ImportError:
    pass
try:
    from tools.web.cdn_tools import *
except ImportError:
    pass
try:
    from tools.web.cms_scanners import *
except ImportError:
    pass
try:
    from tools.web.injection_testing import *
except ImportError:
    pass
try:
    from tools.web.js_analysis import *
except ImportError:
    pass

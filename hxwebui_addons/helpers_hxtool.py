# helpers_hxtool.py
# How add-ons get an HXAPI in HXTool and safely call it.

import logging
from typing import Any, Callable, Tuple

log = logging.getLogger(__name__)


def api_call(func: Callable[..., Tuple[bool, int, Any]], *args, **kwargs) -> Tuple[bool, int, Any]:
    """
    Uniform wrapper for HXAPI calls used by the add-ons.
    Returns (ok, http_code, data). On exception, returns (False, -1, {"error": "..."}).
    """
    try:
        ok, code, data = func(*args, **kwargs)
        return ok, code, data
    except Exception as e:
        log.exception("HX API call failed: %s", e)
        return False, -1, {"error": str(e)}

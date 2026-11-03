# helpers_hxtool.py
# How add-ons get an HXAPI in HXTool and safely call it.

from flask import session
import logging
from typing import Any, Callable, Tuple

from hx_lib import HXAPI

log = logging.getLogger(__name__)

# HXTool stores a serialized HXAPI in the user session with this key
SESSION_KEY = "ht_api_object"


def get_hxapi() -> HXAPI:
    """
    Return an HXAPI object usable against the currently-selected controller.
    Order of precedence:
      1) Current user's session HXAPI (same as core HXTool pages)
      2) Background credential API session from the HXTool scheduler
    """
    # 1) Try the logged-in session first
    api_ser = session.get(SESSION_KEY)
    if api_ser:
        try:
            api = HXAPI.deserialize(api_ser)
            if getattr(api, "hx_host", None) and getattr(api, "hx_port", None):
                return api
        except Exception as e:
            log.exception("Failed to deserialize HX API from session: %s", e)

    # 2) Fallback to background creds via scheduler (if configured)
    try:
        from hxtool_vars import hxtool_global  # created by HXTool on startup
        prof_id = session.get("ht_profileid")
        if prof_id and hasattr(hxtool_global, "hxtool_scheduler"):
            sched = getattr(hxtool_global, "hxtool_scheduler", None)
            if sched and hasattr(sched, "task_hx_api_sessions"):
                task_api = sched.task_hx_api_sessions.get(prof_id)
                if task_api:
                    return task_api
    except Exception as e:
        log.debug("Background API session not available: %s", e)

    # 3) Nothing available
    raise RuntimeError("HXTool background creds or controller missing. Set them in Admin -> HXTool Settings.")


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

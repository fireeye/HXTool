from flask import Blueprint, render_template, request, redirect, url_for, flash
from hxtool_util import valid_session_required
from .helpers_hxtool import api_call
from .security import (
    install_guards,
    valid_numeric_id,
    parse_lines,
    read_upload_lines,
    audit,
    safe_error,
    _CTRL,
)

bp = Blueprint("hostsets", __name__)
install_guards(bp)

@bp.route("/")
@valid_session_required
def index(hx_api_object):
    api = hx_api_object
    ok, code, data = api_call(api.restListHostsets, filter_term={})
    if not ok:
        flash(safe_error("Failed to list host sets", code, data), "error")
    hostsets = data.get("data", {}).get("entries", []) if ok else []
    return render_template("ht_addons_hostsets.html", hostsets=hostsets, api_ok=ok, api_msg=None)

@bp.post("/create")
@valid_session_required
def create(hx_api_object):
    api = hx_api_object
    name = request.form.get("name","").strip()
    if not (1 <= len(name) <= 255) or _CTRL.search(name):
        flash("Invalid host set name.", "error")
        return redirect(url_for("hostsets.index"))
    ok, code, resp = api_call(api.restAddHostset, name, addlist=[])
    audit("create", msg="hostset action", name=name, result="ok" if ok else "fail", code=code)
    if ok:
        flash("Host set created.", "success")
    else:
        flash(safe_error("Failed to create host set", code, resp), "error")
    return redirect(url_for("hostsets.index"))

@bp.post("/modify")
@valid_session_required
def modify(hx_api_object):
    api = hx_api_object
    set_id = request.form.get("hostset_id","").strip()
    set_name = request.form.get("hostset_name","").strip()
    mode = request.form.get("mode","add")
    # IMPORTANT: 'ids' and 'use_hostnames' match the template field names
    ids_text = request.form.get("ids","").strip()
    upload = request.files.get("file")
    use_hostnames = request.form.get("use_hostnames") == "on"

    if not valid_numeric_id(set_id) or set_id == "9" or not (1 <= len(set_name) <= 255) or _CTRL.search(set_name):
        flash("Invalid host set id or name.", "error")
        return redirect(url_for("hostsets.index"))

    if mode not in ("add", "remove"):
        flash("Invalid modification mode.", "error")
        return redirect(url_for("hostsets.index"))

    try:
        ids = parse_lines(ids_text)
        if upload and getattr(upload, "filename", ""):
            ids += read_upload_lines(upload, {".txt"})
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("hostsets.index"))

    ids = list(dict.fromkeys(ids))
    if not (1 <= len(ids) <= 5000):
        flash("Must provide between 1 and 5000 unique IDs or hostnames.", "error")
        return redirect(url_for("hostsets.index"))

    if use_hostnames:
        ok, code, data = api_call(api.restListHosts, limit=100000)
        if not ok:
            flash(safe_error("Failed to list hosts", code, data), "error")
            return redirect(url_for("hostsets.index"))
        lookup = {h.get("hostname"): h.get("_id") for h in data.get("data", {}).get("entries", [])}
        ids = [lookup.get(h) for h in ids]
        ids = [x for x in ids if x]

    if mode == "add":
        ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, addlist=ids)
    else:
        ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, removelist=ids)

    audit("modify", msg="hostset action", id=set_id, mode=mode, count=len(ids), result="ok" if ok else "fail", code=code)
    if ok:
        flash("Host set updated.", "success")
    else:
        flash(safe_error("Failed to update host set", code, resp), "error")
    return redirect(url_for("hostsets.index"))

@bp.post("/delete")
@valid_session_required
def delete(hx_api_object):
    api = hx_api_object
    set_id = request.form.get("hostset_id","").strip()
    confirm = request.form.get("confirm","").strip().upper()
    if not valid_numeric_id(set_id) or set_id == "9":
        flash("Invalid host set id.", "error")
        return redirect(url_for("hostsets.index"))
    if confirm != "DELETE":
        flash('Type "DELETE" in the confirmation box to proceed.', "error")
        return redirect(url_for("hostsets.index"))

    url = api.build_api_route(f"host_sets/{set_id}")
    ok, code, resp = api_call(api.restGetUrl, url, "DELETE")
    ok = bool(ok and code in (200, 202, 204))
    audit("delete", msg="hostset action", id=set_id, result="ok" if ok else "fail", code=code)
    if ok:
        flash("Host set deleted.", "success")
    else:
        flash(safe_error("Delete failed", code, resp), "error")
    return redirect(url_for("hostsets.index"))

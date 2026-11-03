from flask import Blueprint, render_template, request, redirect, url_for, flash
from .helpers_hxtool import get_hxapi, api_call

bp = Blueprint(
    "hostsets",
    __name__,
    url_prefix="/hostsets",
    template_folder="templates",   # ok to keep; we render from app root
    static_folder="static"
)

@bp.route("/")
def index():
    api = get_hxapi()
    ok, code, data = api_call(api.restListHostsets, filter_term={})
    hostsets = data.get("data", {}).get("entries", []) if ok else []
    return render_template("ht_addons_hostsets.html", hostsets=hostsets, api_ok=ok, api_msg=None if ok else data)

@bp.post("/create")
def create():
    api = get_hxapi()
    name = request.form.get("name","").strip()
    if not name:
        flash("Host set name required", "error")
        return redirect(url_for("hostsets.index"))
    ok, code, resp = api_call(api.restAddHostset, name, addlist=[])
    flash("Host set created." if ok else f"Failed: {code} {resp}", "success" if ok else "error")
    return redirect(url_for("hostsets.index"))

@bp.post("/modify")
def modify():
    api = get_hxapi()
    set_id = request.form.get("hostset_id","").strip()
    set_name = request.form.get("hostset_name","").strip()
    mode = request.form.get("mode","add")
    # IMPORTANT: 'ids' and 'use_hostnames' match the template field names
    ids_text = request.form.get("ids","").strip()
    upload = request.files.get("file")
    use_hostnames = request.form.get("use_hostnames") == "on"

    if not (set_id and set_name):
        flash("Missing host set id and/or name", "error")
        return redirect(url_for("hostsets.index"))

    ids = []
    if ids_text:
        ids += [line.strip() for line in ids_text.splitlines() if line.strip()]
    if upload and upload.filename:
        try:
            content = upload.read().decode("utf-8", errors="ignore")
            ids += [line.strip() for line in content.splitlines() if line.strip()]
        except Exception as e:
            flash(f"Could not read uploaded file: {e}", "error")
            return redirect(url_for("hostsets.index"))

    if not ids:
        flash("No IDs or hostnames provided.", "error")
        return redirect(url_for("hostsets.index"))

    ids = list(dict.fromkeys(ids))

    if use_hostnames:
        ok, code, data = api_call(api.restListHosts, limit=100000)
        if not ok:
            flash(f"Failed to list hosts: {code} {data}", "error")
            return redirect(url_for("hostsets.index"))
        lookup = {h.get("hostname"): h.get("_id") for h in data.get("data", {}).get("entries", [])}
        ids = [lookup.get(h) for h in ids]
        ids = [x for x in ids if x]

    if mode == "add":
        ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, addlist=ids)
    else:
        ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, removelist=ids)

    flash("Host set updated." if ok else f"Failed: {code} {resp}", "success" if ok else "error")
    return redirect(url_for("hostsets.index"))

@bp.post("/delete")
def delete():
    api = get_hxapi()
    set_id = request.form.get("hostset_id","").strip()
    confirm = request.form.get("confirm","").strip().upper()
    if not set_id:
        flash("Host set id required", "error")
        return redirect(url_for("hostsets.index"))
    if confirm != "DELETE":
        flash('Type "DELETE" in the confirmation box to proceed.', "error")
        return redirect(url_for("hostsets.index"))

    ok, code, resp = api_call(api.restGetUrl, f"/hx/api/v3/host_sets/{set_id}", "DELETE")
    flash("Host set deleted." if ok else f"Delete failed: {code} {resp}", "success" if ok else "error")
    return redirect(url_for("hostsets.index"))

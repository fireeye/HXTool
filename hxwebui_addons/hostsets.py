from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from hxtool_util import valid_session_required
from .helpers_hxtool import api_call
from .security import (
    install_guards,
    valid_numeric_id,
    valid_agent_id,
    parse_lines,
    read_upload_lines,
    clean_log,
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
    return render_template(
        "ht_addons_hostsets.html",
        hostsets=hostsets,
        api_ok=ok,
        api_msg=None,
        user=session.get("ht_user"),
        controller=f"{getattr(api, 'hx_host', '')}:{getattr(api, 'hx_port', '')}",
    )

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
    set_id = request.form.get("hostset_id", "").strip()
    mode = request.form.get("mode", "add").strip()
    # IMPORTANT: 'ids' and 'use_hostnames' match the template field names
    ids_text = request.form.get("ids", "").strip()
    upload = request.files.get("file")
    use_hostnames = request.form.get("use_hostnames") == "on"

    if not valid_numeric_id(set_id) or set_id == "9":
        flash("Invalid host set id.", "error")
        return redirect(url_for("hostsets.index"))

    if mode not in ("add", "remove"):
        flash("Invalid modification mode.", "error")
        return redirect(url_for("hostsets.index"))

    ok_hs, code_hs, hs_resp = api_call(api.restGetHostset, set_id)
    if not ok_hs or not isinstance(hs_resp, dict) or not hs_resp.get("data"):
        flash(safe_error("Failed to fetch host set", code_hs, hs_resp), "error")
        return redirect(url_for("hostsets.index"))

    hs_data = hs_resp["data"]
    if isinstance(hs_data, list):
        hs = hs_data[0] if hs_data else {}
    else:
        hs = hs_data if isinstance(hs_data, dict) else {}

    hs_type = str(hs.get("type", "")).lower()
    if hs_type != "static":
        flash("Host set is dynamic; membership cannot be modified manually.", "error")
        return redirect(url_for("hostsets.index"))

    set_name = str(hs.get("name", "")).strip()
    if not (1 <= len(set_name) <= 255) or _CTRL.search(set_name):
        flash("Invalid host set name returned by controller.", "error")
        return redirect(url_for("hostsets.index"))

    try:
        ids = parse_lines(ids_text)
        if upload and getattr(upload, "filename", ""):
            ids += read_upload_lines(upload, {".txt"})
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("hostsets.index"))

    raw_entries = list(dict.fromkeys(ids))
    if not (1 <= len(raw_entries) <= 5000):
        flash("Must provide between 1 and 5000 unique IDs or hostnames.", "error")
        return redirect(url_for("hostsets.index"))

    has_hostnames = use_hostnames or any(not valid_agent_id(e) for e in raw_entries)

    matched_ids = []
    unmatched_names = []
    duplicate_hostnames = []

    if has_hostnames:
        ok_h, code_h, h_data = api_call(api.restListHosts, limit=100000)
        if not ok_h:
            flash(safe_error("Failed to list hosts", code_h, h_data), "error")
            return redirect(url_for("hostsets.index"))

        entries = h_data.get("data", {}).get("entries", []) if isinstance(h_data, dict) else []
        by_name: dict[str, list[str]] = {}
        known_ids = set()
        for h in entries:
            if not isinstance(h, dict):
                continue
            hid = h.get("_id")
            if hid:
                known_ids.add(hid)
            hname = (h.get("hostname") or "").strip().lower()
            if hname and hid:
                by_name.setdefault(hname, [])
                if hid not in by_name[hname]:
                    by_name[hname].append(hid)

        for entry in raw_entries:
            if not use_hostnames and valid_agent_id(entry):
                if entry in known_ids:
                    matched_ids.append(entry)
                elif entry.lower() in by_name:
                    matches = by_name[entry.lower()]
                    if len(matches) > 1:
                        duplicate_hostnames.append(entry)
                    matched_ids.extend(matches)
                elif known_ids:
                    unmatched_names.append(entry)
                else:
                    matched_ids.append(entry)
            else:
                matches = by_name.get(entry.lower(), [])
                if not matches:
                    unmatched_names.append(entry)
                else:
                    if len(matches) > 1:
                        duplicate_hostnames.append(entry)
                    matched_ids.extend(matches)
    else:
        matched_ids = list(raw_entries)

    matched_ids = list(dict.fromkeys(matched_ids))
    duplicate_hostnames = list(dict.fromkeys(duplicate_hostnames))

    if not matched_ids:
        preview = ", ".join(clean_log(u, 40) for u in unmatched_names[:10])
        if len(unmatched_names) > 10:
            preview += f" (+{len(unmatched_names) - 10} more)"
        flash(
            f"No matching hosts found (unmatched: {len(unmatched_names)}{': ' + preview if preview else ''}).",
            "error",
        )
        return redirect(url_for("hostsets.index"))

    batches = [matched_ids[i:i + 500] for i in range(0, len(matched_ids), 500)]
    applied_ids_count = 0
    batches_ok = 0
    batches_failed = 0
    last_code = 200

    for idx, batch in enumerate(batches, start=1):
        if mode == "add":
            ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, addlist=batch)
        else:
            ok, code, resp = api_call(api.restModifyHostset, set_name, set_id, removelist=batch)
        last_code = code
        if ok:
            batches_ok += 1
            applied_ids_count += len(batch)
        else:
            batches_failed += 1
            safe_error(f"Batch {idx} failed", code, resp)

    audit(
        "modify",
        msg="hostset action",
        id=set_id,
        mode=mode,
        matched=len(matched_ids),
        applied=applied_ids_count,
        unmatched=len(unmatched_names),
        duplicates=len(duplicate_hostnames),
        batches_ok=batches_ok,
        batches_fail=batches_failed,
        result="ok" if batches_failed == 0 else "fail",
        code=last_code,
    )

    msg = (
        f"Applied {applied_ids_count} of {len(matched_ids)} IDs in {len(batches)} batch(es) "
        f"({batches_ok} ok / {batches_failed} failed); matched {len(matched_ids)}; "
        f"unmatched {len(unmatched_names)}; duplicate hostnames {len(duplicate_hostnames)}."
    )
    if unmatched_names:
        preview = ", ".join(clean_log(u, 40) for u in unmatched_names[:10])
        if len(unmatched_names) > 10:
            preview += f" (+{len(unmatched_names) - 10} more)"
        msg += f" Unmatched: {preview}"

    if batches_failed > 0:
        category = "error"
    elif unmatched_names or duplicate_hostnames:
        category = "warning"
    else:
        category = "success"

    flash(msg, category)
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

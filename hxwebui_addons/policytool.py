from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO
import csv, datetime, json, os, re

from hxtool_util import valid_session_required
from .helpers_hxtool import api_call
from .security import (
    install_guards,
    valid_policy_id,
    parse_lines,
    read_upload_bytes,
    read_upload_lines,
    clean_log,
    audit,
    safe_error,
    csv_safe,
    _CTRL,
)

bp = Blueprint("policytool", __name__)
install_guards(bp)

EXCLUSION_KEYS = ["excludedPaths", "excludedProcessNames", "excludedProcesses", "excludedMD5s", "excludedFiles"]

def _ctx(api) -> dict:
    return {
        "user": session.get("ht_user"),
        "controller": f"{getattr(api, 'hx_host', '')}:{getattr(api, 'hx_port', '')}",
    }

def _list_policies(api) -> tuple[bool, list]:
    ok, code, data = api_call(api.restListPolicies, limit=250)
    policies_list = data.get("data", {}).get("entries", []) if (ok and isinstance(data, dict)) else []
    return bool(ok), policies_list

def _render_page(api, **extra):
    if "policies" in extra and "api_ok" in extra:
        policies = extra.pop("policies")
        ok = bool(extra.pop("api_ok"))
    else:
        ok, policies = _list_policies(api)
        extra.pop("policies", None)
        extra.pop("api_ok", None)
    active_tab = extra.pop("active_tab", "policies")
    lookup_result = extra.pop("lookup_result", None)
    return render_template(
        "ht_addons_policytool.html",
        policies=policies,
        api_ok=ok,
        active_tab=active_tab,
        lookup_result=lookup_result,
        **_ctx(api),
        **extra,
    )

def _section_aliases(section: str):
    s = (section or "").strip().lower().replace(" ", "_")
    aliases_map = {
        "realtime": {"realtime","real_time","real-time","rtid","real_time_indicator_detection"},
        "real_time_indicator_detection": {"realtime","real_time","real-time","rtid","real_time_indicator_detection"},
        "malware_protection": {"malware_protection","malware-protection","mp"},
        "exploit_guard": {"exploit_guard","exploit-guard","exploit_guard_protection","exploit_mitigation","eg"},
        "exploit_guard_protection": {"exploit_guard","exploit-guard","exploit_guard_protection","exploit_mitigation","eg"},
    }
    for k, v in aliases_map.items():
        if s == k or s in v:
            return v
    return {s}

def _choose_module_key(policy_json: dict, ui_category: str) -> str:
    cats = (policy_json or {}).get("categories", {}) or {}
    s = (ui_category or "").lower().replace(" ", "_")
    if s in {"realtime","real_time","real-time","rtid","real_time_indicator_detection"}:
        for k in ["real_time_indicator_detection","realtime","real_time"]:
            if k in cats: return k
        return "real_time_indicator_detection"
    if s in {"malware_protection","malware-protection","mp"}:
        return "malware_protection"
    if s in {"exploit_guard","exploit-guard","exploit_guard_protection","exploit_mitigation","eg"}:
        for k in ["exploit_guard_protection","exploit_guard","exploit_mitigation"]:
            if k in cats: return k
        return "exploit_guard_protection"
    return s

def _item_type_for(module_key: str, type_choice: str) -> str:
    mk = (module_key or "").lower()
    tc = (type_choice or "path").lower()
    if mk in {"real_time_indicator_detection","realtime","real_time"}:
        return "excludedProcessNames" if tc == "process" else "excludedPaths"
    if mk == "malware_protection":
        return "excludedProcesses" if tc == "process" else "excludedFiles"
    if mk in {"exploit_guard_protection","exploit_guard","exploit_mitigation"}:
        return "excludedFiles" if tc == "process" else "excludedPaths"
    return "excludedPaths"

def _pick_platform_key(module_dict, want):
    if not isinstance(module_dict, dict):
        return ""
    plat = [k for k in module_dict.keys() if "platform" in k.lower()]
    if not plat:
        return ""
    want = (want or "").lower()
    def score(k):
        kl = k.lower(); s = 0
        if "win" in kl and want.startswith("platform#win"): s += 2
        if ("osx" in kl or "mac" in kl or "darwin" in kl) and want.startswith("platform#osx"): s += 2
        if "lin" in kl and want.startswith("platform#linux"): s += 2
        if "platform" in kl: s += 1
        return s
    plat.sort(key=score, reverse=True)
    if score(plat[0]) < 2:
        return ""
    return plat[0]

def _validate_rows(policy, rows) -> tuple[list[dict] | None, str | None]:
    if len(rows) > 10000:
        return None, "Too many rows (max 10000)"
    valid_item_types = {"excludedPaths", "excludedProcessNames", "excludedProcesses", "excludedMD5s", "excludedFiles"}
    valid_modules = {"real_time_indicator_detection", "malware_protection", "exploit_guard_protection"}
    categories = policy.get("categories", {}) or {}
    clean_rows = []
    for idx, r in enumerate(rows, start=1):
        if not isinstance(r, dict):
            return None, f"Invalid row at row {idx}"
        item = (r.get("item") or "").strip()
        item_type = (r.get("item_type") or "").strip()
        module = (r.get("module") or "").strip()
        platform = (r.get("platform") or "").strip()

        if item_type not in valid_item_types:
            return None, f"Invalid exclusion row at row {idx}"
        if module not in valid_modules or module not in categories:
            return None, f"Invalid exclusion row at row {idx}"
        mod_dict = categories.get(module)
        if platform == "":
            if isinstance(mod_dict, dict) and any("platform" in k.lower() for k in mod_dict.keys()):
                return None, f"Missing required platform at row {idx}"
        else:
            if not (isinstance(mod_dict, dict) and isinstance(mod_dict.get(platform), dict) and "platform" in platform):
                return None, f"Invalid exclusion row at row {idx}"
        if not (1 <= len(item) <= 1024) or _CTRL.search(item):
            return None, f"Invalid exclusion row at row {idx}"
        if item_type == "excludedMD5s" and not re.fullmatch(r'[A-Fa-f0-9]{32}', item):
            return None, f"Invalid exclusion row at row {idx}"

        clean_rows.append({
            "item": item,
            "item_type": item_type,
            "module": module,
            "platform": platform,
        })
    return clean_rows, None

@bp.route("/")
@valid_session_required
def index(hx_api_object):
    api = hx_api_object
    ok, policies = _list_policies(api)
    if not ok:
        flash("Failed to list policies from controller.", "warning")
    return _render_page(api, policies=policies, api_ok=ok, api_msg=None)

@bp.post("/clone")
@valid_session_required
def clone_policy(hx_api_object):
    api = hx_api_object
    src_id = request.form.get("source_policy_id", "").strip()
    new_name = request.form.get("new_policy_name", "").strip()

    if not valid_policy_id(src_id) or not (1 <= len(new_name) <= 255) or _CTRL.search(new_name):
        flash("Invalid source policy id or new policy name.", "error")
        return redirect(url_for("policytool.index"))

    ok, code, resp = api_call(api.restGetPolicy, src_id)
    if not ok or not isinstance(resp, dict) or not resp.get("data"):
        flash(safe_error("Failed to read source policy", code, resp), "error")
        return redirect(url_for("policytool.index"))

    src = (resp["data"][0] if isinstance(resp["data"], list) else resp["data"])
    payload = {
        "policy_type_id": src.get("policy_type_id"),
        "default": False,
        "name": new_name,
        "description": src.get("description", ""),
        "enabled": src.get("enabled", True),
        "priority": src.get("priority", 1),
        "categories": src.get("categories", {}),
    }
    ok, code, resp = api_call(api.restCreatePolicy, payload)
    audit("clone", msg="policy action", src=src_id, name=new_name, result="ok" if ok else "fail", code=code)
    if ok:
        flash("Policy cloned successfully.", "success")
    else:
        flash(safe_error("Clone failed", code, resp), "error")
    return redirect(url_for("policytool.index"))

@bp.get("/export")
@valid_session_required
def export_policy_json(hx_api_object):
    api = hx_api_object
    policy_id = request.args.get("policy_id", "").strip()
    if not valid_policy_id(policy_id):
        flash("Invalid policy id.", "error")
        return redirect(url_for("policytool.index"))

    ok, code, resp = api_call(api.restGetPolicy, policy_id)
    if not ok or not isinstance(resp, dict) or not resp.get("data"):
        flash(safe_error("Failed to fetch policy", code, resp), "error")
        return redirect(url_for("policytool.index"))

    policy = (resp["data"][0] if isinstance(resp["data"], list) else resp["data"])
    sanitized = {
        k: policy[k]
        for k in ("policy_type_id", "name", "description", "enabled", "priority", "categories")
        if k in policy
    }
    raw_bytes = json.dumps(sanitized, indent=2).encode("utf-8")
    filename = f"{secure_filename(policy.get('name', '')) or 'policy'}_policy_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    audit("export_policy_json", msg="policy action", id=policy_id, result="ok", code=200)
    return send_file(BytesIO(raw_bytes), mimetype="application/json", as_attachment=True, download_name=filename)

@bp.post("/import")
@valid_session_required
def import_policy_json(hx_api_object):
    api = hx_api_object
    file = request.files.get("file")
    new_name = request.form.get("new_policy_name", "").strip()

    try:
        raw = read_upload_bytes(file, {".json"})
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("policytool.index"))

    if not raw:
        flash("No JSON policy file uploaded.", "error")
        return redirect(url_for("policytool.index"))

    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        flash("Invalid JSON policy file.", "error")
        return redirect(url_for("policytool.index"))

    if not isinstance(doc, dict):
        flash("Invalid JSON policy file.", "error")
        return redirect(url_for("policytool.index"))

    name = new_name if new_name else str(doc.get("name") or "").strip()
    if not (1 <= len(name) <= 255) or _CTRL.search(name):
        flash("Invalid policy name.", "error")
        return redirect(url_for("policytool.index"))

    pti = doc.get("policy_type_id")
    if not isinstance(pti, str) or not (1 <= len(pti.strip()) <= 128) or _CTRL.search(pti):
        flash("Invalid policy_type_id in JSON policy.", "error")
        return redirect(url_for("policytool.index"))

    categories = doc.get("categories")
    if not isinstance(categories, dict) or len(categories) == 0 or not all(isinstance(v, dict) for v in categories.values()):
        flash("Invalid categories structure in JSON policy.", "error")
        return redirect(url_for("policytool.index"))

    for mod_name, mod_dict in categories.items():
        has_plat = any("platform" in k.lower() for k in mod_dict.keys())
        if has_plat:
            for k, v in mod_dict.items():
                if "platform" in k.lower():
                    if not isinstance(v, dict):
                        flash(f"Invalid platform structure in module '{mod_name}'.", "error")
                        return redirect(url_for("policytool.index"))
                    for ek in EXCLUSION_KEYS:
                        if ek in v:
                            if not isinstance(v[ek], list) or not all(isinstance(x, str) for x in v[ek]):
                                flash(f"Invalid exclusion list '{ek}' in module '{mod_name}'.", "error")
                                return redirect(url_for("policytool.index"))
        else:
            for ek in EXCLUSION_KEYS:
                if ek in mod_dict:
                    if not isinstance(mod_dict[ek], list) or not all(isinstance(x, str) for x in mod_dict[ek]):
                        flash(f"Invalid exclusion list '{ek}' in module '{mod_name}'.", "error")
                        return redirect(url_for("policytool.index"))

    clean_rows, err_msg = _validate_rows(doc, _exclusions_to_rows(doc))
    if err_msg is not None or clean_rows is None:
        flash(err_msg or "Invalid exclusions in JSON policy.", "error")
        return redirect(url_for("policytool.index"))

    raw_priority = doc.get("priority", 1)
    priority = int(raw_priority) if (isinstance(raw_priority, int) and not isinstance(raw_priority, bool)) else 1

    payload = {
        "policy_type_id": str(doc["policy_type_id"]).strip(),
        "default": False,
        "name": name,
        "description": str(doc.get("description") or "")[:1024],
        "enabled": bool(doc.get("enabled", True)),
        "priority": priority,
        "categories": doc["categories"],
    }

    ok, code, resp = api_call(api.restCreatePolicy, payload)
    audit("import_policy_json", msg="policy action", name=name, result="ok" if ok else "fail", code=code)
    if ok:
        flash("Policy imported successfully.", "success")
    else:
        flash(safe_error("Policy import failed", code, resp), "error")
    return redirect(url_for("policytool.index"))

@bp.post("/exclusions/copy")
@valid_session_required
def copy_exclusions(hx_api_object):
    api = hx_api_object
    src_id = request.form.get("source_policy_id", "").strip()
    dst_id = request.form.get("target_policy_id", "").strip()
    module_filter = request.form.get("module", "all").strip().lower()
    mode = request.form.get("mode", "append").strip().lower()

    valid_modules = {"all", "real_time_indicator_detection", "malware_protection", "exploit_guard_protection"}
    if (
        not valid_policy_id(src_id)
        or not valid_policy_id(dst_id)
        or src_id == dst_id
        or module_filter not in valid_modules
        or mode not in ("append", "overwrite")
    ):
        flash("Invalid source/target policy id, module, or mode.", "error")
        return redirect(url_for("policytool.index"))

    ok_s, code_s, resp_s = api_call(api.restGetPolicy, src_id)
    if not ok_s or not isinstance(resp_s, dict) or not resp_s.get("data"):
        flash(safe_error("Failed to fetch source policy", code_s, resp_s), "error")
        return redirect(url_for("policytool.index"))

    ok_d, code_d, resp_d = api_call(api.restGetPolicy, dst_id)
    if not ok_d or not isinstance(resp_d, dict) or not resp_d.get("data"):
        flash(safe_error("Failed to fetch target policy", code_d, resp_d), "error")
        return redirect(url_for("policytool.index"))

    src_policy = resp_s["data"][0]
    target_policy = resp_d["data"][0]
    target_cats = target_policy.get("categories", {}) or {}

    rows = _exclusions_to_rows(src_policy)
    if module_filter != "all":
        if module_filter not in target_cats:
            flash(f"Target policy does not contain module '{module_filter}'.", "error")
            return redirect(url_for("policytool.index"))
        to_match = {m.lower() for m in _section_aliases(module_filter)}
        rows = [r for r in rows if r.get("module", "").lower() in to_match]

    if not rows:
        flash("No exclusions found in source policy for the selected module.", "error")
        return redirect(url_for("policytool.index"))

    clean_rows, err_msg = _validate_rows(target_policy, rows)
    if err_msg or clean_rows is None:
        flash(f"Target policy incompatible: {err_msg}", "error")
        return redirect(url_for("policytool.index"))

    if mode == "overwrite":
        if module_filter == "all":
            target_modules = [
                m for m in ("real_time_indicator_detection", "malware_protection", "exploit_guard_protection")
                if m in target_cats
            ]
        else:
            target_modules = [module_filter] if module_filter in target_cats else []

        for mod in target_modules:
            mod_dict = target_cats.get(mod)
            if not isinstance(mod_dict, dict):
                continue
            plat_keys = [k for k in mod_dict.keys() if "platform" in k.lower()]
            if plat_keys:
                for pk in plat_keys:
                    sub = mod_dict.get(pk)
                    if isinstance(sub, dict):
                        for ek in EXCLUSION_KEYS:
                            if ek in sub:
                                sub[ek] = []
            else:
                for ek in EXCLUSION_KEYS:
                    if ek in mod_dict:
                        mod_dict[ek] = []

    updated = _apply_exclusions(target_policy, clean_rows, overwrite=(mode == "overwrite"))
    ok, code, resp = api_call(api.restModifyPolicy, dst_id, updated)
    audit(
        "copy_exclusions",
        msg="policy action",
        src=src_id,
        dst=dst_id,
        module=module_filter,
        mode=mode,
        count=len(clean_rows),
        result="ok" if ok else "fail",
        code=code,
    )
    if ok:
        flash(f"Copied {len(clean_rows)} exclusion(s) to target policy.", "success")
    else:
        flash(safe_error("Failed to copy exclusions", code, resp), "error")
    return redirect(url_for("policytool.index"))

@bp.get("/exclusions/export")
@valid_session_required
def export_exclusions(hx_api_object):
    api = hx_api_object
    policy_id = request.args.get("policy_id", "").strip()
    section = request.args.get("section", "all").strip().lower()

    if not valid_policy_id(policy_id) or section not in {"all", "real_time_indicator_detection", "malware_protection", "exploit_guard_protection"}:
        flash("Invalid policy id or section.", "error")
        return redirect(url_for("policytool.index"))

    ok, code, resp = api_call(api.restGetPolicy, policy_id)
    if not ok or not isinstance(resp, dict) or not resp.get("data"):
        flash(safe_error("Failed to fetch policy", code, resp), "error")
        return redirect(url_for("policytool.index"))

    policy = (resp["data"][0] if isinstance(resp["data"], list) else resp["data"])
    rows = _exclusions_to_rows(policy)
    if section != "all":
        to_match = {m.lower() for m in _section_aliases(section)}
        rows = [r for r in rows if (r.get("module","").lower() in to_match)]

    out = StringIO()
    w = csv.DictWriter(out, fieldnames=["item","item_type","module","platform"])
    w.writeheader()
    for r in rows:
        w.writerow({k: csv_safe(v) for k, v in r.items()})
    mem = BytesIO(out.getvalue().encode("utf-8"))
    base = secure_filename(policy.get('name', '')) or 'policy'
    filename = f"{base}_exclusions_{section}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    audit("export_exclusions", msg="policy action", id=policy_id, section=section, count=len(rows), result="ok", code=200)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

@bp.post("/exclusions/import")
@valid_session_required
def import_exclusions(hx_api_object):
    api = hx_api_object
    policy_id = request.form.get("policy_id", "").strip()
    mode = request.form.get("mode", "append")
    ui_category = request.form.get("category", "").strip().lower()
    type_choice = request.form.get(f"type_{ui_category}", "path")
    mp_platform = request.form.get("mp_platform", "platform#win").strip().lower()
    file = request.files.get("file")
    paste_text = (request.form.get("paste_text") or request.form.get("items") or "").strip()

    if not valid_policy_id(policy_id) or mode not in ("append", "overwrite"):
        flash("Invalid policy id or import mode.", "error")
        return redirect(url_for("policytool.index"))

    has_upload = bool(file and getattr(file, "filename", ""))
    ext = os.path.splitext((file.filename or "").lower())[1] if has_upload else ""

    try:
        file_lines = read_upload_lines(file, {".txt", ".csv"}) if has_upload else []
        pasted_lines = parse_lines(paste_text) if paste_text else []
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("policytool.index"))

    needs_plain_validation = bool(pasted_lines or (has_upload and ext == ".txt"))
    if needs_plain_validation:
        if (
            ui_category not in {"real_time_indicator_detection", "malware_protection", "exploit_guard_protection"}
            or type_choice not in ("process", "path")
            or mp_platform not in ("platform#win", "platform#osx", "platform#linux")
        ):
            flash("Invalid category, exclusion type, or platform selection.", "error")
            return redirect(url_for("policytool.index"))

    ok, code, resp = api_call(api.restGetPolicy, policy_id)
    if not ok or not isinstance(resp, dict) or not resp.get("data"):
        flash(safe_error("Failed to fetch policy", code, resp), "error")
        return redirect(url_for("policytool.index"))
    policy = (resp["data"][0] if isinstance(resp["data"], list) else resp["data"])

    import_rows = []
    if has_upload and file_lines:
        if ext == ".csv":
            reader = csv.DictReader(file_lines)
            if not reader.fieldnames or not {"item", "item_type", "module"}.issubset(set(reader.fieldnames)):
                flash("CSV file must contain 'item', 'item_type', and 'module' columns.", "error")
                return redirect(url_for("policytool.index"))
            for row in reader:
                item = (row.get("item") or "").strip()
                item = item[1:] if item[:1] == "'" and item[1:2] in ("=", "+", "-", "@") else item
                item_type = (row.get("item_type") or "").strip()
                module = (row.get("module") or "").strip()
                platform = (row.get("platform") or "").strip()
                import_rows.append({
                    "item": item,
                    "item_type": item_type,
                    "module": module,
                    "platform": platform,
                })
        else:
            module_key = _choose_module_key(policy, ui_category)
            item_type = _item_type_for(module_key, type_choice)
            for item in file_lines:
                import_rows.append({"item": item, "item_type": item_type, "module": module_key, "platform": ""})

    if pasted_lines:
        module_key = _choose_module_key(policy, ui_category)
        item_type = _item_type_for(module_key, type_choice)
        for item in pasted_lines:
            import_rows.append({"item": item, "item_type": item_type, "module": module_key, "platform": ""})

    if not import_rows:
        flash("No exclusions provided via file or pasted list", "error")
        return redirect(url_for("policytool.index"))

    if any((r.get("module","").lower() == "malware_protection") for r in import_rows):
        needs_pk = any(
            r.get("module", "").lower() == "malware_protection" and not r.get("platform")
            for r in import_rows
        )
        pk = _pick_platform_key(policy.get("categories", {}).get("malware_protection", {}), mp_platform)
        if needs_pk and pk == "":
            flash("No matching platform in policy for malware_protection.", "error")
            return redirect(url_for("policytool.index"))
        for r in import_rows:
            if r.get("module","").lower() == "malware_protection" and not r.get("platform"):
                r["platform"] = pk or ""

    clean_rows, err_msg = _validate_rows(policy, import_rows)
    if err_msg is not None or clean_rows is None:
        flash(err_msg or "Invalid exclusion rows.", "error")
        return redirect(url_for("policytool.index"))

    updated = _apply_exclusions(policy, clean_rows, overwrite=(mode=="overwrite"))
    ok2, code2, resp2 = api_call(api.restModifyPolicy, policy_id, updated)
    audit("import_exclusions", msg="policy action", id=policy_id, mode=mode, count=len(clean_rows), result="ok" if ok2 else "fail", code=code2)
    if ok2:
        flash("Exclusions imported.", "success")
    else:
        flash(safe_error("Import failed", code2, resp2), "error")
    return redirect(url_for("policytool.index"))

@bp.get("/agent-policy")
@bp.get("/agent/policy")
@valid_session_required
def agent_policy(hx_api_object):
    api = hx_api_object
    q = (request.args.get("q") or "").strip()
    if not q:
        return _render_page(api, active_tab="lookup")

    if len(q) > 255 or _CTRL.search(q):
        flash("Invalid query.", "error")
        return redirect(url_for("policytool.index"))

    ok, code, data = api_call(api.restListHosts, search_term=q, limit=50)
    entries = data.get("data", {}).get("entries", []) if (ok and isinstance(data, dict)) else []

    if not entries:
        flash(safe_error("Host not found", code, data) if not ok else "No host found matching query.", "error")
        return _render_page(api, active_tab="lookup")

    ql = q.lower()
    agent = entries[0]
    for candidate in entries:
        if not isinstance(candidate, dict):
            continue
        cid = str(candidate.get("_id") or "").strip().lower()
        chost = str(candidate.get("hostname") or "").strip().lower()
        if ql in (cid, chost):
            agent = candidate
            break

    agent_id = str(agent.get("_id") or "").strip()
    if not agent_id:
        flash("Matched host entry is missing agent ID.", "error")
        return _render_page(api, active_tab="lookup")

    ok_s, code_s, sum_data = api_call(api.restGetHostSummary, agent_id)
    raw_s = sum_data.get("data") if isinstance(sum_data, dict) else None
    if isinstance(raw_s, list) and raw_s:
        raw_s = raw_s[0]
    host_summary = raw_s if (ok_s and isinstance(raw_s, dict) and raw_s) else agent

    ok_hs, code_hs, hs_data = api_call(api.restListHostsets, limit=500)
    all_sets = hs_data.get("data", {}).get("entries", []) if (ok_hs and isinstance(hs_data, dict)) else []
    if len(all_sets) >= 500:
        flash("Host set scan capped at 500 sets; results may be partial.", "warning")

    memberships = []
    search_val = agent.get("hostname") or agent_id
    for hs in all_sets:
        if not isinstance(hs, dict):
            continue
        sid = hs.get("_id")
        if sid is None:
            continue
        ok_m, _, m_data = api_call(
            api.restListHostsInHostset,
            sid,
            limit=500,
            search_term=search_val,
        )
        m_entries = m_data.get("data", {}).get("entries", []) if (ok_m and isinstance(m_data, dict)) else []
        if any(isinstance(e, dict) and str(e.get("_id") or "") == agent_id for e in m_entries):
            memberships.append({
                "_id": sid,
                "persist_id": hs.get("persist_id"),
                "name": hs.get("name"),
                "type": hs.get("type"),
            })

    member_keys = (
        {str(m.get("_id")) for m in memberships if m.get("_id")}
        | {str(m.get("persist_id")) for m in memberships if m.get("persist_id")}
    )

    ok_map, _, map_data = api_call(api.restGetUrl, api.build_api_route("host_set_policies"), include_params=True, limit=1000)
    mappings = map_data.get("data", {}).get("entries", []) if (ok_map and isinstance(map_data, dict)) else []

    policy_cache = {}
    applied = []
    for m in mappings:
        if not isinstance(m, dict):
            continue
        m_hs_key = str(m.get("persist_id") or m.get("host_set_id") or m.get("_id") or "")
        if m_hs_key in member_keys:
            pid = m.get("policy_id")
            if not pid:
                continue
            if pid not in policy_cache:
                ok_p, _, pdata = api_call(api.restGetPolicy, pid)
                pdoc = {}
                if ok_p and isinstance(pdata, dict) and pdata.get("data"):
                    raw_p = pdata["data"]
                    pdoc = raw_p[0] if isinstance(raw_p, list) else raw_p
                    if not isinstance(pdoc, dict):
                        pdoc = {}
                policy_cache[pid] = pdoc
            pdoc = policy_cache[pid]

            hs_name = m_hs_key
            for mem in memberships:
                if m_hs_key in (str(mem.get("_id") or ""), str(mem.get("persist_id") or "")):
                    hs_name = mem.get("name") or m_hs_key
                    break

            applied.append({
                "host_set_id": m_hs_key,
                "host_set_name": hs_name,
                "policy_id": pid,
                "policy_name": pdoc.get("name"),
                "priority": pdoc.get("priority"),
            })

    audit(
        "agent_lookup",
        msg="policy action",
        query=clean_log(q, 64),
        agent_id=agent_id,
        memberships=len(memberships),
        applied=len(applied),
        result="ok",
        code=200,
    )

    return _render_page(
        api,
        active_tab="lookup",
        lookup_result={
            "query": q,
            "agent": host_summary,
            "memberships": memberships,
            "applied": applied,
        },
    )

def _exclusions_to_rows(policy_json):
    exclusion_keys = ["excludedPaths","excludedProcessNames","excludedProcesses","excludedMD5s","excludedFiles"]
    rows = []
    categories = policy_json.get("categories", {}) or {}
    for module_name, module_data in categories.items():
        def add_items(container, platform=""):
            if not isinstance(container, dict): return
            for key in exclusion_keys:
                vals = container.get(key)
                if isinstance(vals, list):
                    for item in vals:
                        rows.append({"item": str(item), "item_type": key, "module": module_name, "platform": platform})
        if isinstance(module_data, dict) and any("platform" in k for k in module_data.keys()):
            for p in [k for k in module_data.keys() if "platform" in k]:
                add_items(module_data.get(p, {}), platform=p)
        else:
            add_items(module_data, platform="")
    return rows

def _apply_exclusions(policy_json, rows, overwrite=False):
    categories = policy_json.get("categories", {}) or {}
    from collections import defaultdict
    bucket = defaultdict(list)
    for r in rows:
        bucket[(r.get("module",""), r.get("platform",""), r.get("item_type",""))].append(r.get("item",""))
    for (module, platform, item_type), items in bucket.items():
        if module not in categories or not isinstance(categories[module], dict):
            categories[module] = {}
        container = categories[module]
        dest = container.setdefault(platform, {}) if platform else container
        cur = dest.get(item_type, [])
        if not isinstance(cur, list): cur = []
        dest[item_type] = sorted(set(items)) if overwrite else sorted(set(cur + items))
    policy_json["categories"] = categories
    return policy_json

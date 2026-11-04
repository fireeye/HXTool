from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO
import csv, datetime, os, re

from hxtool_util import valid_session_required
from .helpers_hxtool import api_call
from .security import (
    install_guards,
    valid_policy_id,
    parse_lines,
    read_upload_lines,
    audit,
    safe_error,
    csv_safe,
    _CTRL,
)

bp = Blueprint("policytool", __name__)
install_guards(bp)

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
    if not plat: return ""
    want = (want or "").lower()
    def score(k):
        kl = k.lower(); s = 0
        if "win" in kl and want.startswith("platform#win"): s += 2
        if ("osx" in kl or "mac" in kl or "darwin" in kl) and want.startswith("platform#osx"): s += 2
        if "lin" in kl and want.startswith("platform#linux"): s += 2
        if "platform" in kl: s += 1
        return s
    plat.sort(key=score, reverse=True)
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
        if platform != "":
            mod_dict = categories.get(module)
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
    ok, code, data = api_call(api.restListPolicies)
    if not ok:
        flash(safe_error("Failed to list policies", code, data), "error")
    policies = data.get("data", {}).get("entries", []) if ok else []
    return render_template("ht_addons_policytool.html", policies=policies, api_ok=ok, api_msg=None)

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

    src = resp["data"][0]
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

    policy = resp["data"][0]
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
    filename = f"{base}_exclusions_{section}_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
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
    paste_text = request.form.get("paste_text", "").strip()

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
    policy = resp["data"][0]

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
        pk = _pick_platform_key(policy.get("categories", {}).get("malware_protection", {}), mp_platform)
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

@bp.get("/agent/policy")
@valid_session_required
def agent_policy(hx_api_object):
    api = hx_api_object
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("ht_addons_policytool.html", policies=[], api_ok=True, api_msg=None)
    if not (1 <= len(q) <= 255) or _CTRL.search(q):
        flash("Invalid agent search query.", "error")
        return redirect(url_for("policytool.index"))

    ok, code, data = api_call(api.restListHosts, search_term=q, limit=5)
    if not ok or not isinstance(data, dict) or not data.get("data", {}).get("entries"):
        flash(safe_error("Host not found", code, data), "error")
        return redirect(url_for("policytool.index"))
    agent = data["data"]["entries"][0]
    agent_id = agent.get("_id")

    ok_s, code_s, data_s = api_call(api.restGetHostSummary, agent_id)
    host_summary = data_s.get("data") if ok_s else agent

    ok, code, hs_data = api_call(api.restListHostsets, limit=100000)
    memberships, id_to_name = [], {}
    if ok:
        for hs in hs_data.get("data", {}).get("entries", []):
            hid = hs.get("_id") or hs.get("id"); nm = hs.get("name")
            id_to_name[hid] = nm
            ok_m, code_m, data_m = api_call(api.restListHostsInHostset, host_set_id=hid, search_term=agent_id, limit=1)
            if ok_m and data_m.get("data", {}).get("entries"):
                memberships.append({"_id": hid, "name": nm})

    ok_p, code_p, polmap = api_call(api.restGetUrl, "/hx/api/v3/host_set_policies", include_params=True)
    applied = []
    if ok_p:
        for entry in polmap.get("data", {}).get("entries", []):
            hs_persist = entry.get("persist_id")
            if hs_persist in {m["_id"] for m in memberships}:
                pol_id = entry.get("policy_id")
                ok_g, code_g, pol_data = api_call(api.restGetPolicy, pol_id)
                if ok_g and pol_data.get("data"):
                    pol = pol_data["data"][0]
                    applied.append({
                        "host_set_id": hs_persist, "host_set_name": id_to_name.get(hs_persist, hs_persist),
                        "policy_id": pol.get("_id"), "policy_name": pol.get("name"),
                        "priority": pol.get("priority")
                    })

    # For now we just flash summary to user via UI or keep on page
    return render_template("ht_addons_policytool.html", policies=[], api_ok=True, api_msg=None)

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

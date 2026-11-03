from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from io import StringIO, BytesIO
import csv, datetime

from .helpers_hxtool import get_hxapi, api_call

bp = Blueprint(
    "policytool",
    __name__,
    url_prefix="/policytool",
    template_folder="templates",   # ok to keep; we render from app root
    static_folder="static"
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

@bp.route("/")
def index():
    api = get_hxapi()
    ok, code, data = api_call(api.restListPolicies)
    policies = data.get("data", {}).get("entries", []) if ok else []
    return render_template("ht_addons_policytool.html", policies=policies, api_ok=ok, api_msg=None if ok else data)

@bp.post("/clone")
def clone_policy():
    api = get_hxapi()
    src_id = request.form.get("source_policy_id", "").strip()
    new_name = request.form.get("new_policy_name", "").strip()

    ok, code, resp = api_call(api.restGetPolicy, src_id)
    if not ok or not resp.get("data"):
        flash(f"Failed to read source policy: {code} {resp}", "error")
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
    flash("Policy cloned successfully." if ok else f"Clone failed: {code} {resp}", "success" if ok else "error")
    return redirect(url_for("policytool.index"))

@bp.get("/exclusions/export")
def export_exclusions():
    policy_id = request.args.get("policy_id", "").strip()
    section = request.args.get("section", "all").strip().lower()
    api = get_hxapi()

    ok, code, resp = api_call(api.restGetPolicy, policy_id)
    if not ok or not resp.get("data"):
        flash(f"Failed to fetch policy: {code} {resp}", "error")
        return redirect(url_for("policytool.index"))

    policy = resp["data"][0]
    rows = _exclusions_to_rows(policy)
    if section != "all":
        to_match = {m.lower() for m in _section_aliases(section)}
        rows = [r for r in rows if (r.get("module","").lower() in to_match)]

    out = StringIO()
    w = csv.DictWriter(out, fieldnames=["item","item_type","module","platform"])
    w.writeheader()
    for r in rows: w.writerow(r)
    mem = BytesIO(out.getvalue().encode("utf-8"))
    filename = f"{policy.get('name','policy')}_exclusions_{section}_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

@bp.post("/exclusions/import")
def import_exclusions():
    api = get_hxapi()
    policy_id = request.form.get("policy_id", "").strip()
    mode = request.form.get("mode", "append")
    ui_category = request.form.get("category", "").strip().lower()
    type_choice = request.form.get(f"type_{ui_category}", "path")
    mp_platform = request.form.get("mp_platform", "platform#win").strip().lower()
    file = request.files.get("file")
    paste_text = request.form.get("paste_text", "").strip()

    if not policy_id:
        flash("Missing policy id", "error")
        return redirect(url_for("policytool.index"))

    ok, code, resp = api_call(api.restGetPolicy, policy_id)
    if not ok or not resp.get("data"):
        flash(f"Failed to fetch policy: {code} {resp}", "error")
        return redirect(url_for("policytool.index"))
    policy = resp["data"][0]

    import_rows = []
    if file and file.filename:
        name = (file.filename or "").lower()
        content = file.read().decode("utf-8", errors="ignore")
        lines_from_file = [ln.strip() for ln in content.splitlines() if ln.strip()]
        if name.endswith(".csv") or (lines_from_file and (',' in lines_from_file[0])):
            reader = csv.DictReader(lines_from_file)
            for row in reader:
                import_rows.append(row)
        else:
            module_key = _choose_module_key(policy, ui_category or "real_time_indicator_detection")
            item_type = _item_type_for(module_key, type_choice)
            for item in lines_from_file:
                import_rows.append({"item": item, "item_type": item_type, "module": module_key, "platform": ""})

    if paste_text:
        module_key = _choose_module_key(policy, ui_category or "real_time_indicator_detection")
        item_type = _item_type_for(module_key, type_choice)
        for item in [ln.strip() for ln in paste_text.splitlines() if ln.strip()]:
            import_rows.append({"item": item, "item_type": item_type, "module": module_key, "platform": ""})

    if not import_rows:
        flash("No exclusions provided via file or pasted list", "error")
        return redirect(url_for("policytool.index"))

    if any((r.get("module","").lower() == "malware_protection") for r in import_rows):
        pk = _pick_platform_key(policy.get("categories", {}).get("malware_protection", {}), mp_platform)
        for r in import_rows:
            if r.get("module","").lower() == "malware_protection" and not r.get("platform"):
                r["platform"] = pk or ""

    updated = _apply_exclusions(policy, import_rows, overwrite=(mode=="overwrite"))
    ok, code, resp = api_call(api.restModifyPolicy, policy_id, updated)
    flash("Exclusions imported." if ok else f"Import failed: {code} {resp}", "success" if ok else "error")
    return redirect(url_for("policytool.index"))

@bp.get("/agent/policy")
def agent_policy():
    api = get_hxapi()
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("ht_addons_policytool.html", policies=[], api_ok=True, api_msg=None)

    ok, code, data = api_call(api.restListHosts, search_term=q, limit=5)
    if not ok or not data.get("data", {}).get("entries"):
        flash(f"Host not found: {code} {data}", "error")
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

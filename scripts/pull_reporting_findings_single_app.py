#!/usr/bin/env python3
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import pandas as pd
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

API_TIMEOUT_S = 60
POLL_INTERVAL_S = 15
MAX_POLL_S = 20 * 60  # 20 minutes


def must_env(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def opt_env(name: str) -> str:
    return os.getenv(name, "").strip()


def validate_date_yyyy_mm_dd(s: str) -> None:
    # Your tenant enforced date-only in earlier runs.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise SystemExit("LAST_UPDATED_START_DATE must be YYYY-MM-DD (date only), e.g. 2025-12-01")


def ensure_out_dir() -> None:
    os.makedirs("out", exist_ok=True)


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def hmac_auth_from_env() -> RequestsAuthPluginVeracodeHMAC:
    api_id = must_env("VERACODE_API_ID")
    api_key = must_env("VERACODE_API_KEY")
    return RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)


# -------------------------
# Applications API (resolve IDs by name)
# -------------------------

def applications_lookup_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, name: str) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications"
    r = requests.get(url, params={"name": name, "page": 0, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?name={name} failed: {r.status_code}\n{r.text}")
    return r.json()


def extract_first_application(apps_resp: Dict[str, Any]) -> Dict[str, Any]:
    embedded = apps_resp.get("_embedded") or {}
    apps = embedded.get("applications") or []
    if not isinstance(apps, list) or not apps:
        raise SystemExit("No applications returned. Check APPLICATION_NAME or permissions.")
    if not isinstance(apps[0], dict):
        raise SystemExit("Unexpected Applications API response shape.")
    return apps[0]


def resolve_app_ids(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_name: str) -> Tuple[Optional[int], Optional[str], Dict[str, Any]]:
    resp = applications_lookup_by_name(api_base, auth, app_name)
    app0 = extract_first_application(resp)

    numeric_id = app0.get("id")
    guid = app0.get("guid")

    app_id: Optional[int] = None
    if numeric_id is not None:
        try:
            app_id = int(str(numeric_id))
        except Exception:
            app_id = None

    app_guid: Optional[str] = guid if isinstance(guid, str) and guid else None
    return app_id, app_guid, app0


# -------------------------
# Sandboxes API (resolve SANDBOX_NAME -> sandbox id/guid)
# REST equivalent: GET /appsec/v1/applications/{applicationGuid}/sandboxes  [oai_citation:6‡docs.veracode.com](https://docs.veracode.com/r/r_getsandboxlist?utm_source=chatgpt.com)
# -------------------------

def list_sandboxes(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, page: int = 0) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications/{app_guid}/sandboxes"
    r = requests.get(url, params={"page": page, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?page={page} failed: {r.status_code}\n{r.text}")
    return r.json()


def extract_sandboxes(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    embedded = resp.get("_embedded") or {}
    for key in ("sandboxes", "sandbox"):
        v = embedded.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    for v in embedded.values():
        if isinstance(v, list) and (not v or isinstance(v[0], dict)):
            return [x for x in v if isinstance(x, dict)]
    return []


def sandbox_fields(sb: Dict[str, Any]) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Return (sandbox_id, sandbox_guid, sandbox_name) best-effort.
    Different tenants may use slightly different keys.
    """
    name = sb.get("name") or sb.get("sandbox_name")
    guid = sb.get("guid") or sb.get("sandbox_guid")
    sid = sb.get("id") or sb.get("sandbox_id")

    sandbox_id: Optional[int] = None
    if sid is not None:
        try:
            sandbox_id = int(str(sid))
        except Exception:
            sandbox_id = None

    sandbox_guid = guid if isinstance(guid, str) and guid else None
    sandbox_name = name if isinstance(name, str) and name else None
    return sandbox_id, sandbox_guid, sandbox_name


def resolve_sandbox_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, sandbox_name: str) -> Dict[str, Any]:
    # page 0 is usually enough; keep a bounded paging loop for safety
    for page in range(0, 10):
        resp = list_sandboxes(api_base, auth, app_guid, page=page)
        sbs = extract_sandboxes(resp)
        if not sbs:
            break
        for sb in sbs:
            _, _, nm = sandbox_fields(sb)
            if nm == sandbox_name:
                return sb
    raise SystemExit(f"Sandbox '{sandbox_name}' not found for this application. Check exact name/case.")


# -------------------------
# Reporting API
# Docs show filters including policy_sandbox; platform updates add sandbox ID filtering.  [oai_citation:7‡docs.veracode.com](https://docs.veracode.com/r/Reporting_REST_API)
# -------------------------

def reporting_post_generate(
    api_base: str,
    auth: RequestsAuthPluginVeracodeHMAC,
    last_updated_start: str,
    app_id: Optional[int],
    policy_sandbox: Optional[str],
    sandbox_id: Optional[int],
) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report"

    payload: Dict[str, Any] = {
        "report_type": "FINDINGS",
        "last_updated_start_date": last_updated_start,
    }

    # Many tenants accept app_id.
    if app_id is not None:
        payload["app_id"] = app_id

    # Policy vs Sandbox selector (if provided)
    if policy_sandbox:
        payload["policy_sandbox"] = policy_sandbox

    # Sandbox filter (supported in newer versions per Veracode updates)
    if sandbox_id is not None:
        payload["sandbox_id"] = sandbox_id

    r = requests.post(url, json=payload, auth=auth, timeout=API_TIMEOUT_S)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}

    if r.status_code >= 400:
        # Tenant may reject some fields; retry progressively (remove sandbox_id, then policy_sandbox, then app_id)
        # so customers still get output (client-side filtering will apply).
        def try_post(pl: Dict[str, Any]) -> Tuple[int, Dict[str, Any], str]:
            rr = requests.post(url, json=pl, auth=auth, timeout=API_TIMEOUT_S)
            try:
                bb = rr.json()
            except Exception:
                bb = {"raw": rr.text}
            return rr.status_code, bb, rr.text

        # 1) remove sandbox_id
        if "sandbox_id" in payload:
            p1 = dict(payload)
            p1.pop("sandbox_id", None)
            code, bb, txt = try_post(p1)
            if code < 400:
                return bb
            body = bb

        # 2) remove policy_sandbox
        if "policy_sandbox" in payload:
            p2 = dict(payload)
            p2.pop("sandbox_id", None)
            p2.pop("policy_sandbox", None)
            code, bb, txt = try_post(p2)
            if code < 400:
                return bb
            body = bb

        # 3) remove app_id (portfolio-wide)
        p3 = {"report_type": "FINDINGS", "last_updated_start_date": last_updated_start}
        code, bb, txt = try_post(p3)
        if code < 400:
            return bb
        body = bb

        write_json("out/report_create.json", body)
        raise SystemExit(f"POST {url} failed: {r.status_code}\n{r.text}")

    return body


def reporting_extract_report_id(created: Dict[str, Any]) -> Optional[str]:
    embedded = created.get("_embedded")
    if isinstance(embedded, dict):
        rid = embedded.get("id")
        if isinstance(rid, str) and rid:
            return rid
    rid2 = created.get("id")
    if isinstance(rid2, str) and rid2:
        return rid2
    return None


def reporting_get_page(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, report_id: str, page: int) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report/{report_id}"
    r = requests.get(url, params={"page": page}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?page={page} failed: {r.status_code}\n{r.text}")
    return r.json()


def reporting_is_ready(obj: Dict[str, Any]) -> bool:
    status = str(
        obj.get("status")
        or obj.get("state")
        or (obj.get("_embedded") or {}).get("status")
        or ""
    ).upper()
    return status in {"COMPLETED", "COMPLETE", "READY", "FINISHED"}


def reporting_total_pages(obj: Dict[str, Any]) -> int:
    embedded = obj.get("_embedded") or {}
    meta = embedded.get("page_metadata") or {}
    tp = meta.get("total_pages")
    if tp is None:
        return 1
    try:
        return int(tp)
    except Exception:
        return 1


def reporting_extract_findings(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    embedded = obj.get("_embedded") or {}
    findings = embedded.get("findings")
    if isinstance(findings, list):
        return [f for f in findings if isinstance(f, dict)]
    return []


# -------------------------
# Filter findings to the single app + sandbox (client-side, safe)
# -------------------------

def find_app_name_in_finding(f: Dict[str, Any]) -> Optional[str]:
    for k in ("app_name", "application_name", "applicationName"):
        v = f.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def find_sandbox_name_in_finding(f: Dict[str, Any]) -> Optional[str]:
    for k in ("sandbox_name", "sandboxName"):
        v = f.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def find_sandbox_id_in_finding(f: Dict[str, Any]) -> Optional[int]:
    for k in ("sandbox_id", "sandboxId"):
        v = f.get(k)
        if v is None:
            continue
        try:
            return int(str(v))
        except Exception:
            pass
    return None


def filter_findings(findings: List[Dict[str, Any]], app_name: str, sandbox_name: str, sandbox_id: Optional[int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        if find_app_name_in_finding(f) != app_name:
            continue
        if sandbox_name:
            # Prefer sandbox_name match; if not present, fall back to sandbox_id
            fn = find_sandbox_name_in_finding(f)
            if fn:
                if fn != sandbox_name:
                    continue
            elif sandbox_id is not None:
                fid = find_sandbox_id_in_finding(f)
                if fid is None or fid != sandbox_id:
                    continue
        out.append(f)
    return out


# -------------------------
# Lossless Excel export (capture everything)
# -------------------------

def to_cell(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return v


def findings_to_dataframe_lossless(findings: List[Dict[str, Any]]) -> pd.DataFrame:
    all_keys = set()
    for f in findings:
        if isinstance(f, dict):
            all_keys.update(f.keys())

    rows: List[Dict[str, Any]] = []
    for f in findings:
        row: Dict[str, Any] = {}
        for k in all_keys:
            row[k] = to_cell(f.get(k))
        rows.append(row)

    df = pd.DataFrame(rows)
    df = df.reindex(sorted(df.columns), axis=1)
    return df


def export_findings_lossless_excel(findings: List[Dict[str, Any]], out_xlsx: str) -> None:
    df_flat = findings_to_dataframe_lossless(findings)
    df_raw = pd.DataFrame({
        "finding_json": [
            json.dumps(f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            for f in findings
        ]
    })

    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df_flat.to_excel(writer, index=False, sheet_name="findings_flat")
        df_raw.to_excel(writer, index=False, sheet_name="findings_raw_json")


def main() -> None:
    ensure_out_dir()

    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_name = must_env("APPLICATION_NAME")
    last_updated_start = must_env("LAST_UPDATED_START_DATE")
    validate_date_yyyy_mm_dd(last_updated_start)
    sandbox_name = opt_env("SANDBOX_NAME")

    auth = hmac_auth_from_env()

    # Resolve app ids
    app_id, app_guid, app_obj = resolve_app_ids(api_base, auth, app_name)
    write_json("out/application_lookup.json", app_obj)
    print(f"Resolved application: name={app_name}, id={app_id}, guid={app_guid}")

    sandbox_id: Optional[int] = None
    sandbox_guid: Optional[str] = None
    if sandbox_name:
        if not app_guid:
            raise SystemExit("Application GUID is required to resolve sandboxes but was not found.")
        sb_obj = resolve_sandbox_by_name(api_base, auth, app_guid, sandbox_name)
        sandbox_id, sandbox_guid, _ = sandbox_fields(sb_obj)
        write_json("out/sandbox_lookup.json", sb_obj)
        print(f"Resolved sandbox: name={sandbox_name}, sandbox_id={sandbox_id}, sandbox_guid={sandbox_guid}")

    # policy_sandbox: use "Policy" by default; "Sandbox" if SANDBOX_NAME provided
    policy_sandbox = "Sandbox" if sandbox_name else "Policy"

    # Generate report (try server-side filters; fall back if rejected)
    created = reporting_post_generate(
        api_base=api_base,
        auth=auth,
        last_updated_start=last_updated_start,
        app_id=app_id,
        policy_sandbox=policy_sandbox,
        sandbox_id=sandbox_id,
    )
    write_json("out/report_create.json", created)

    report_id = reporting_extract_report_id(created)
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # Poll until ready (page 0)
    start = time.time()
    page0 = None
    while True:
        page0 = reporting_get_page(api_base, auth, report_id, page=0)
        write_json("out/report_page0_latest.json", page0)
        if reporting_is_ready(page0):
            break
        if time.time() - start > MAX_POLL_S:
            raise SystemExit("Timed out waiting for report readiness.")
        time.sleep(POLL_INTERVAL_S)

    # Paginate deterministically
    total_pages = reporting_total_pages(page0) if page0 else 1
    pages: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    for p in range(total_pages):
        obj = reporting_get_page(api_base, auth, report_id, page=p)
        pages.append(obj)
        all_findings.extend(reporting_extract_findings(obj))

    write_json("out/report_pages.json", pages)
    write_json("out/findings_portfolio_flat.json", all_findings)

    # Client-side filter to the requested app + sandbox (if provided)
    scoped = filter_findings(all_findings, app_name=app_name, sandbox_name=sandbox_name, sandbox_id=sandbox_id)
    suffix = f"{app_name}" + (f"__sandbox__{sandbox_name}" if sandbox_name else "")
    write_json(f"out/findings_single_app_{suffix}.json", scoped)

    # Lossless Excel
    out_xlsx = f"out/findings_single_app_{suffix}.xlsx"
    export_findings_lossless_excel(scoped, out_xlsx)

    print(f"report_id={report_id}")
    print(f"total_pages={total_pages}")
    print(f"findings_total={len(all_findings)}")
    print(f"findings_scoped={len(scoped)}")
    print(f"Wrote JSON: out/findings_single_app_{suffix}.json")
    print(f"Wrote Excel (lossless): {out_xlsx}")


if __name__ == "__main__":
    main()

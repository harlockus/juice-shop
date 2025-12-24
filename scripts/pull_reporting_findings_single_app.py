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


# -------------------------
# Helpers
# -------------------------

def must_env(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def validate_date_yyyy_mm_dd(s: str) -> None:
    # Your tenant requires YYYY-MM-DD date-only.
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
# Applications API (resolve IDs)
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
# Reporting API
# -------------------------

def reporting_post_generate(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, last_updated_start: str) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report"
    payload = {
        "report_type": "FINDINGS",
        "last_updated_start_date": last_updated_start,  # must be YYYY-MM-DD for your tenant
    }
    r = requests.post(url, json=payload, auth=auth, timeout=API_TIMEOUT_S)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}

    if r.status_code >= 400:
        write_json("out/report_create.json", body)
        raise SystemExit(f"POST {url} failed: {r.status_code}\n{r.text}")

    return body


def reporting_extract_report_id(created: Dict[str, Any]) -> Optional[str]:
    # Your tenant returns report id nested under _embedded.id
    embedded = created.get("_embedded")
    if isinstance(embedded, dict):
        rid = embedded.get("id")
        if isinstance(rid, str) and rid:
            return rid
    # fallback for other shapes
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
# Filter findings to the single app
# -------------------------

def find_app_id_in_finding(f: Dict[str, Any]) -> Optional[int]:
    candidates = [
        f.get("app_id"),
        f.get("application_id"),
        f.get("applicationId"),
        (f.get("application") or {}).get("id"),
        (f.get("application") or {}).get("app_id"),
    ]
    for c in candidates:
        if c is None:
            continue
        try:
            return int(str(c))
        except Exception:
            pass
    return None


def find_app_guid_in_finding(f: Dict[str, Any]) -> Optional[str]:
    candidates = [
        f.get("application_guid"),
        f.get("app_guid"),
        (f.get("application") or {}).get("guid"),
    ]
    for c in candidates:
        if isinstance(c, str) and c:
            return c
    return None


def find_app_name_in_finding(f: Dict[str, Any]) -> Optional[str]:
    for k in ("app_name", "application_name", "applicationName"):
        v = f.get(k)
        if isinstance(v, str) and v:
            return v
    app_obj = f.get("application")
    if isinstance(app_obj, dict):
        v = app_obj.get("name")
        if isinstance(v, str) and v:
            return v
    return None


def filter_findings_to_app(
    findings: List[Dict[str, Any]],
    target_name: str,
    target_id: Optional[int],
    target_guid: Optional[str],
) -> List[Dict[str, Any]]:
    keep: List[Dict[str, Any]] = []

    for f in findings:
        name = find_app_name_in_finding(f)
        if name and name == target_name:
            keep.append(f)
            continue

        fid = find_app_id_in_finding(f)
        if target_id is not None and fid is not None and fid == target_id:
            keep.append(f)
            continue

        fguid = find_app_guid_in_finding(f)
        if target_guid is not None and fguid is not None and fguid == target_guid:
            keep.append(f)
            continue

    return keep


# -------------------------
# Lossless Excel export (capture everything)
# -------------------------

def to_cell(v: Any) -> Any:
    """Excel-safe value; preserve dict/list as JSON string so nothing is lost."""
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return v


def findings_to_dataframe_lossless(findings: List[Dict[str, Any]]) -> pd.DataFrame:
    # Union of keys across all findings
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
    # Deterministic column order
    df = df.reindex(sorted(df.columns), axis=1)
    return df


def export_findings_lossless_excel(findings: List[Dict[str, Any]], out_xlsx: str) -> None:
    df_flat = findings_to_dataframe_lossless(findings)

    # True lossless backup: entire finding JSON in one column
    df_raw = pd.DataFrame({
        "finding_json": [
            json.dumps(f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            for f in findings
        ]
    })

    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df_flat.to_excel(writer, index=False, sheet_name="findings_flat")
        df_raw.to_excel(writer, index=False, sheet_name="findings_raw_json")


# -------------------------
# Main
# -------------------------

def main() -> None:
    ensure_out_dir()

    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_name = must_env("APPLICATION_NAME")
    last_updated_start = must_env("LAST_UPDATED_START_DATE")
    validate_date_yyyy_mm_dd(last_updated_start)

    auth = hmac_auth_from_env()

    # 1) Resolve application ids (id + guid)
    app_id, app_guid, app_obj = resolve_app_ids(api_base, auth, app_name)
    write_json("out/application_lookup.json", app_obj)
    print(f"Resolved application: name={app_name}, id={app_id}, guid={app_guid}")

    # 2) Create report
    created = reporting_post_generate(api_base, auth, last_updated_start)
    write_json("out/report_create.json", created)

    report_id = reporting_extract_report_id(created)
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # 3) Poll until report ready
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

    # 4) Deterministic pagination
    total_pages = reporting_total_pages(page0) if page0 else 1
    pages: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    for p in range(total_pages):
        obj = reporting_get_page(api_base, auth, report_id, page=p)
        pages.append(obj)
        all_findings.extend(reporting_extract_findings(obj))

    write_json("out/report_pages.json", pages)
    write_json("out/findings_portfolio_flat.json", all_findings)

    # 5) Filter to the single application
    single_app_findings = filter_findings_to_app(all_findings, app_name, app_id, app_guid)
    write_json(f"out/findings_single_app_{app_name}.json", single_app_findings)

    # 6) Lossless Excel (captures everything)
    out_xlsx = f"out/findings_single_app_{app_name}.xlsx"
    export_findings_lossless_excel(single_app_findings, out_xlsx)

    print(f"report_id={report_id}")
    print(f"total_pages={total_pages}")
    print(f"findings_total={len(all_findings)}")
    print(f"findings_for_app={len(single_app_findings)}")
    print(f"Wrote JSON: out/findings_single_app_{app_name}.json")
    print(f"Wrote Excel (lossless): {out_xlsx}")


if __name__ == "__main__":
    main()

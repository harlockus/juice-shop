#!/usr/bin/env python3
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

API_TIMEOUT_S = 60
POLL_INTERVAL_S = 15
MAX_POLL_S = 20 * 60  # 20 minutes


def must_env(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def validate_date_yyyy_mm_dd(s: str) -> None:
    # Your tenant required YYYY-MM-DD (date-only). Keep it strict.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise SystemExit("LAST_UPDATED_START_DATE must be YYYY-MM-DD (date only), e.g. 2025-12-01")


def hmac_auth_from_env() -> RequestsAuthPluginVeracodeHMAC:
    api_id = must_env("VERACODE_API_ID")
    api_key = must_env("VERACODE_API_KEY")
    # Veracode provides this Python signing library for HMAC auth.  [oai_citation:5‡Veracode Docs](https://docs.veracode.com/r/c_hmac_signing_example_python)
    return RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)


# ---------------------------
# Applications API (resolve IDs)
# ---------------------------

def list_apps_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, name: str) -> Dict[str, Any]:
    # Applications list call is documented (paged).  [oai_citation:6‡Veracode Docs](https://docs.veracode.com/r/r_applications_list)
    url = f"{api_base}/appsec/v1/applications"
    r = requests.get(url, params={"name": name, "page": 0, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?name={name} failed: {r.status_code}\n{r.text}")
    return r.json()


def extract_first_application(apps_resp: Dict[str, Any]) -> Dict[str, Any]:
    embedded = apps_resp.get("_embedded") or {}
    apps = embedded.get("applications") or []
    if not isinstance(apps, list) or not apps:
        raise SystemExit("No applications returned. Check APPLICATION_NAME spelling or permissions.")
    if not isinstance(apps[0], dict):
        raise SystemExit("Unexpected Applications API response shape.")
    return apps[0]


def get_app_ids(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_name: str) -> Tuple[Optional[int], Optional[str], Dict[str, Any]]:
    resp = list_apps_by_name(api_base, auth, app_name)
    app0 = extract_first_application(resp)
    numeric_id = app0.get("id")
    guid = app0.get("guid")
    try:
        numeric_id_int = int(numeric_id) if numeric_id is not None else None
    except Exception:
        numeric_id_int = None
    guid_str = str(guid) if isinstance(guid, str) and guid else None
    return numeric_id_int, guid_str, app0


# ---------------------------
# Reporting API
# ---------------------------

def post_generate_findings_report(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, last_updated_start: str, app_id: Optional[int]) -> Dict[str, Any]:
    """
    Veracode Reporting REST API: POST /appsec/v1/analytics/report to generate a report.  [oai_citation:7‡Veracode Docs](https://docs.veracode.com/r/Reporting_REST_API?utm_source=chatgpt.com)

    Docs show app_id as a possible filter field for FINDINGS, but some tenants reject filters.
    We'll:
      - try with app_id if present
      - if tenant rejects app_id field, retry without it
    """
    url = f"{api_base}/appsec/v1/analytics/report"
    base_payload = {
        "report_type": "FINDINGS",
        "last_updated_start_date": last_updated_start,
    }

    # First attempt: include app_id if we have it (docs show it as valid for FINDINGS).  [oai_citation:8‡Veracode Docs](https://docs.veracode.com/r/Reporting_REST_API?utm_source=chatgpt.com)
    if app_id is not None:
        payload = dict(base_payload)
        payload["app_id"] = app_id
    else:
        payload = base_payload

    r = requests.post(url, json=payload, auth=auth, timeout=API_TIMEOUT_S)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}

    if r.status_code >= 400:
        # If tenant rejects app_id or fields, retry without app_id (portfolio-wide, client filter later)
        if app_id is not None:
            r2 = requests.post(url, json=base_payload, auth=auth, timeout=API_TIMEOUT_S)
            try:
                body2 = r2.json()
            except Exception:
                body2 = {"raw": r2.text}
            if r2.status_code >= 400:
                write_json("out/report_create.json", body2)
                raise SystemExit(f"POST {url} failed: {r2.status_code}\n{r2.text}")
            return body2

        write_json("out/report_create.json", body)
        raise SystemExit(f"POST {url} failed: {r.status_code}\n{r.text}")

    return body


def extract_report_id(created: Dict[str, Any]) -> Optional[str]:
    # Your tenant returns report id nested under _embedded.id (you already observed this).
    embedded = created.get("_embedded")
    if isinstance(embedded, dict):
        rid = embedded.get("id")
        if isinstance(rid, str) and rid:
            return rid
    # fallback if other tenants return top-level id
    rid2 = created.get("id")
    if isinstance(rid2, str) and rid2:
        return rid2
    return None


def get_report_page(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, report_id: str, page: int) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report/{report_id}"
    r = requests.get(url, params={"page": page}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?page={page} failed: {r.status_code}\n{r.text}")
    return r.json()


def is_ready(report_obj: Dict[str, Any]) -> bool:
    status = str(
        report_obj.get("status")
        or report_obj.get("state")
        or (report_obj.get("_embedded") or {}).get("status")
        or ""
    ).upper()
    return status in {"COMPLETED", "COMPLETE", "READY", "FINISHED"}


def extract_items(page_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    embedded = page_obj.get("_embedded") or {}
    findings = embedded.get("findings")
    if isinstance(findings, list):
        return findings
    return []


def total_pages_from_page0(page0: Dict[str, Any]) -> Optional[int]:
    embedded = page0.get("_embedded") or {}
    meta = embedded.get("page_metadata") or {}
    tp = meta.get("total_pages")
    try:
        return int(tp) if tp is not None else None
    except Exception:
        return None


def infer_app_id(item: Dict[str, Any]) -> Optional[int]:
    # Try common shapes; if your tenant uses a different key, you can add it here.
    candidates = [
        item.get("app_id"),
        item.get("application_id"),
        item.get("applicationId"),
        (item.get("application") or {}).get("id"),
    ]
    for c in candidates:
        if c is None:
            continue
        try:
            return int(str(c))
        except Exception:
            pass
    return None


def infer_app_guid(item: Dict[str, Any]) -> Optional[str]:
    candidates = [
        item.get("application_guid"),
        item.get("app_guid"),
        (item.get("application") or {}).get("guid"),
    ]
    for c in candidates:
        if isinstance(c, str) and c:
            return c
    return None


def main() -> None:
    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_name = must_env("APPLICATION_NAME")
    last_updated_start = must_env("LAST_UPDATED_START_DATE")
    validate_date_yyyy_mm_dd(last_updated_start)

    auth = hmac_auth_from_env()

    # 1) Resolve correct application IDs from Applications API
    app_id, app_guid, app_obj = get_app_ids(api_base, auth, app_name)
    write_json("out/application_lookup.json", app_obj)
    print(f"Resolved application: name={app_name}, id={app_id}, guid={app_guid}")

    # 2) Generate Findings report (try app_id filter; fallback portfolio-wide)
    created = post_generate_findings_report(api_base, auth, last_updated_start, app_id)
    write_json("out/report_create.json", created)

    report_id = extract_report_id(created)
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # 3) Poll until report is ready (page 0)
    start = time.time()
    page0 = None
    while True:
        page0 = get_report_page(api_base, auth, report_id, page=0)
        write_json("out/report_page0_latest.json", page0)
        if is_ready(page0):
            break
        if time.time() - start > MAX_POLL_S:
            raise SystemExit("Timed out waiting for report readiness.")
        time.sleep(POLL_INTERVAL_S)

    # 4) Deterministic pagination using total_pages from page0
    tp = total_pages_from_page0(page0) if page0 else None
    if tp is None:
        # fallback: at least fetch page0 only
        tp = 1

    pages: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    for p in range(tp):
        obj = get_report_page(api_base, auth, report_id, page=p)
        pages.append(obj)
        all_findings.extend(extract_items(obj))

    write_json("out/report_pages.json", pages)
    write_json("out/findings_portfolio_flat.json", all_findings)

    # 5) Filter findings down to this application only
    only_app: List[Dict[str, Any]] = []
    unknown = 0
    for f in all_findings:
        fid = infer_app_id(f)
        fguid = infer_app_guid(f)
        if fid is None and fguid is None:
            unknown += 1
            continue
        if app_id is not None and fid == app_id:
            only_app.append(f)
            continue
        if app_guid is not None and fguid == app_guid:
            only_app.append(f)
            continue

    write_json(f"out/findings_single_app_{app_name}.json", only_app)

    print(f"report_id={report_id}")
    print(f"total_pages={tp}")
    print(f"findings_total={len(all_findings)}")
    print(f"unknown_app_fields={unknown}")
    print(f"findings_for_app={len(only_app)}")
    print(f"Wrote out/findings_single_app_{app_name}.json")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import os
import time
from typing import Any, Dict, List

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


def is_ready(report_obj: Dict[str, Any]) -> bool:
    status = str(report_obj.get("status") or report_obj.get("state") or "").upper()
    return status in {"COMPLETED", "COMPLETE", "READY", "FINISHED"}


def extract_items(page_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Reporting API responses commonly embed lists under _embedded.
    Extract findings defensively.
    """
    embedded = page_obj.get("_embedded") or {}
    if isinstance(embedded.get("findings"), list):
        return embedded["findings"]
    # fallback: first list-of-dicts
    for v in embedded.values():
        if isinstance(v, list) and (not v or isinstance(v[0], dict)):
            return v
    # fallback: direct
    if isinstance(page_obj.get("findings"), list):
        return page_obj["findings"]
    return []


def post_generate_report(
    api_base: str,
    auth: RequestsAuthPluginVeracodeHMAC,
    app_id: int,
    last_updated_start: str,
) -> Dict[str, Any]:
    """
    Generate a Findings report and attempt to scope it to one app via filters.
    Some tenants/versions may differ; we also client-filter later as a safety net.
    """
    url = f"{api_base}/appsec/v1/analytics/report"

    payload = {
        "report_type": "FINDINGS",
        "last_updated_start_date": last_updated_start,
        "filters": {
            "app_id": [app_id]
        },
    }

    r = requests.post(url, json=payload, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"POST {url} failed: {r.status_code}\n{r.text}")
    return r.json()


def get_report_page(
    api_base: str,
    auth: RequestsAuthPluginVeracodeHMAC,
    report_id: str,
    page: int,
) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report/{report_id}"
    r = requests.get(url, params={"page": page}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?page={page} failed: {r.status_code}\n{r.text}")
    return r.json()


def client_filter_by_app_id(items: List[Dict[str, Any]], app_id: int) -> List[Dict[str, Any]]:
    """
    Safety net: enforce app scope client-side in case server-side filter differs.
    """
    keep: List[Dict[str, Any]] = []
    for it in items:
        candidates = [
            it.get("app_id"),
            it.get("application_id"),
            (it.get("application") or {}).get("id"),
            (it.get("application") or {}).get("app_id"),
        ]
        if any(str(c) == str(app_id) for c in candidates if c is not None):
            keep.append(it)
    return keep


def main() -> None:
    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_id = int(must_env("APP_ID"))
    last_updated_start = must_env("LAST_UPDATED_START_DATE")

    # ✅ FIX: read creds from env (GitHub Secrets) and pass explicitly to auth plugin
    api_id = must_env("VERACODE_API_ID")
    api_key = must_env("VERACODE_API_KEY")
    auth = RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)

    # 1) Generate report
    created = post_generate_report(api_base, auth, app_id, last_updated_start)
    write_json("out/report_create.json", created)

    report_id = str(created.get("id") or "")
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # 2) Poll until ready (page 0)
    start = time.time()
    while True:
        page0 = get_report_page(api_base, auth, report_id, page=0)
        write_json("out/report_page0_latest.json", page0)

        if is_ready(page0):
            break

        if time.time() - start > MAX_POLL_S:
            raise SystemExit("Timed out waiting for report readiness (see out/report_page0_latest.json).")

        time.sleep(POLL_INTERVAL_S)

    # 3) Paginate pages until empty
    pages: List[Dict[str, Any]] = []
    all_items: List[Dict[str, Any]] = []

    page = 0
    while True:
        obj = get_report_page(api_base, auth, report_id, page=page)
        pages.append(obj)

        items = extract_items(obj)
        if not items:
            break

        all_items.extend(items)
        page += 1

    write_json("out/report_pages.json", pages)

    # 4) Enforce single-app scope client-side
    filtered = client_filter_by_app_id(all_items, app_id)
    write_json(f"out/findings_{app_id}.json", filtered)

    print(f"report_id={report_id}")
    print(f"pages_fetched={len(pages)}")
    print(f"items_total={len(all_items)}")
    print(f"items_after_app_filter={len(filtered)}")
    print(f"wrote out/findings_{app_id}.json")


if __name__ == "__main__":
    main()

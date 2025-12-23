#!/usr/bin/env python3
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

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


def validate_date_yyyy_mm_dd(s: str) -> None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise SystemExit("LAST_UPDATED_START_DATE must be YYYY-MM-DD (date only), e.g. 2025-12-01")


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def is_ready(report_obj: Dict[str, Any]) -> bool:
    status = str(
        report_obj.get("status")
        or report_obj.get("state")
        or report_obj.get("_embedded", {}).get("status")
        or ""
    ).upper()
    return status in {"COMPLETED", "COMPLETE", "READY", "FINISHED"}


def extract_items(page_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    embedded = page_obj.get("_embedded") or {}
    if isinstance(embedded.get("findings"), list):
        return embedded["findings"]
    for v in embedded.values():
        if isinstance(v, list) and (not v or isinstance(v[0], dict)):
            return v
    if isinstance(page_obj.get("findings"), list):
        return page_obj["findings"]
    return []


def infer_app_id(item: Dict[str, Any]) -> Optional[int]:
    candidates = [
        item.get("app_id"),
        item.get("application_id"),
        item.get("applicationId"),
        (item.get("application") or {}).get("id"),
        (item.get("application") or {}).get("app_id"),
        (item.get("application") or {}).get("application_id"),
    ]
    for c in candidates:
        if c is None:
            continue
        try:
            return int(str(c))
        except Exception:
            pass
    return None


def extract_report_id(created: Dict[str, Any]) -> Optional[str]:
    """
    Your tenant returns the report ID here:
      created["_embedded"]["id"]
    """
    embedded = created.get("_embedded")
    if isinstance(embedded, dict):
        rid = embedded.get("id")
        if isinstance(rid, str) and rid:
            return rid
    return None


def post_generate_report(
    api_base: str,
    auth: RequestsAuthPluginVeracodeHMAC,
    last_updated_start: str,
) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report"
    payload = {
        "report_type": "FINDINGS",
        "last_updated_start_date": last_updated_start,
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


def main() -> None:
    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_id = int(must_env("APP_ID"))
    last_updated_start = must_env("LAST_UPDATED_START_DATE")
    validate_date_yyyy_mm_dd(last_updated_start)

    api_id = must_env("VERACODE_API_ID")
    api_key = must_env("VERACODE_API_KEY")
    auth = RequestsAuthPluginVeracodeHMAC(
        api_key_id=api_id,
        api_key_secret=api_key,
    )

    # 1) Generate report
    created = post_generate_report(api_base, auth, last_updated_start)
    write_json("out/report_create.json", created)

    report_id = extract_report_id(created)
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # 2) Poll until ready
    start = time.time()
    while True:
        page0 = get_report_page(api_base, auth, report_id, page=0)
        write_json("out/report_page0_latest.json", page0)

        if is_ready(page0):
            break

        if time.time() - start > MAX_POLL_S:
            raise SystemExit("Timed out waiting for report readiness.")

        time.sleep(POLL_INTERVAL_S)

    # 3) Paginate all pages
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
    write_json("out/findings_portfolio_flat.json", all_items)

    # 4) Filter to your application
    only_app: List[Dict[str, Any]] = []
    unknown = 0

    for it in all_items:
        aid = infer_app_id(it)
        if aid is None:
            unknown += 1
            continue
        if aid == app_id:
            only_app.append(it)

    write_json(f"out/findings_{app_id}.json", only_app)

    print(f"report_id={report_id}")
    print(f"pages_fetched={len(pages)}")
    print(f"items_total={len(all_items)}")
    print(f"unknown_app_id_items={unknown}")
    print(f"items_for_app_{app_id}={len(only_app)}")
    print(f"wrote out/findings_{app_id}.json")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


API_TIMEOUT_S = 60


# -------------------------
# Generic helpers
# -------------------------

def env(name: str, required: bool = False) -> str:
    v = os.getenv(name, "").strip()
    if required and not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def hmac_auth() -> RequestsAuthPluginVeracodeHMAC:
    api_id = env("VERACODE_API_ID", required=True)
    api_key = env("VERACODE_API_KEY", required=True)
    return RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)


def safe_get_json(r: requests.Response) -> Dict[str, Any]:
    try:
        return r.json()
    except Exception:
        return {"raw": r.text}


# -------------------------
# Applications API: resolve app GUID by name
# -------------------------

def app_lookup_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_name: str) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications"
    r = requests.get(url, params={"name": app_name, "page": 0, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?name={app_name} failed: {r.status_code}\n{r.text}")
    return r.json()


def extract_first_app(apps_resp: Dict[str, Any]) -> Dict[str, Any]:
    embedded = apps_resp.get("_embedded") or {}
    apps = embedded.get("applications") or []
    if not isinstance(apps, list) or not apps:
        raise SystemExit("No applications returned. Check APPLICATION_NAME or permissions.")
    if not isinstance(apps[0], dict):
        raise SystemExit("Unexpected Applications API response shape.")
    return apps[0]


def resolve_app_guid(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_name: str) -> Tuple[str, Dict[str, Any]]:
    apps_resp = app_lookup_by_name(api_base, auth, app_name)
    app0 = extract_first_app(apps_resp)
    app_guid = app0.get("guid")
    if not isinstance(app_guid, str) or not app_guid:
        raise SystemExit("Application GUID not found in Applications API response.")
    return app_guid, app0


# -------------------------
# Sandbox lookup: resolve SANDBOX_NAME -> sandbox GUID
# -------------------------

def list_sandboxes(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, page: int) -> Dict[str, Any]:
    # Common REST pattern for sandboxes list for an application profile.
    url = f"{api_base}/appsec/v1/applications/{app_guid}/sandboxes"
    r = requests.get(url, params={"page": page, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?page={page} failed: {r.status_code}\n{r.text}")
    return r.json()


def extract_sandboxes(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    embedded = resp.get("_embedded") or {}
    # Different tenants sometimes use "sandboxes" or "sandbox" as the embedded list key.
    for key in ("sandboxes", "sandbox"):
        v = embedded.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    # fallback: look for first list-of-dicts inside _embedded
    for v in embedded.values():
        if isinstance(v, list) and (not v or isinstance(v[0], dict)):
            return [x for x in v if isinstance(x, dict)]
    return []


def total_pages(resp: Dict[str, Any]) -> Optional[int]:
    # Some APIs use "page" at top level; others embed page metadata.
    p = resp.get("page")
    if isinstance(p, dict) and "total_pages" in p:
        try:
            return int(p["total_pages"])
        except Exception:
            return None
    embedded = resp.get("_embedded") or {}
    meta = embedded.get("page_metadata") or {}
    if "total_pages" in meta:
        try:
            return int(meta["total_pages"])
        except Exception:
            return None
    return None


def sandbox_name_of(sb: Dict[str, Any]) -> Optional[str]:
    # Try common name fields.
    for k in ("name", "sandbox_name"):
        v = sb.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def sandbox_guid_of(sb: Dict[str, Any]) -> Optional[str]:
    for k in ("guid", "sandbox_guid"):
        v = sb.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def resolve_sandbox_guid_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, sandbox_name: str) -> Tuple[str, Dict[str, Any]]:
    # Page through sandbox list until found.
    page = 0
    found_obj: Optional[Dict[str, Any]] = None

    # Determine page count if available
    first = list_sandboxes(api_base, auth, app_guid, page=0)
    sbs = extract_sandboxes(first)

    # Try page 0 first
    for sb in sbs:
        if sandbox_name_of(sb) == sandbox_name:
            found_obj = sb
            break

    tp = total_pages(first)
    if found_obj is None and tp is not None:
        for page in range(1, tp):
            resp = list_sandboxes(api_base, auth, app_guid, page=page)
            for sb in extract_sandboxes(resp):
                if sandbox_name_of(sb) == sandbox_name:
                    found_obj = sb
                    break
            if found_obj is not None:
                break

    # If tp not known, do bounded scan (avoid infinite loops)
    if found_obj is None and tp is None:
        for page in range(1, 20):
            resp = list_sandboxes(api_base, auth, app_guid, page=page)
            sbs = extract_sandboxes(resp)
            if not sbs:
                break
            for sb in sbs:
                if sandbox_name_of(sb) == sandbox_name:
                    found_obj = sb
                    break
            if found_obj is not None:
                break

    if found_obj is None:
        raise SystemExit(f"Sandbox name not found: '{sandbox_name}'. Check exact spelling/case in Veracode.")

    sb_guid = sandbox_guid_of(found_obj)
    if not sb_guid:
        raise SystemExit("Sandbox GUID not found in sandbox object.")

    return sb_guid, found_obj


# -------------------------
# Summary Report API
# -------------------------

def get_summary_report(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, sandbox_guid: Optional[str]) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v2/applications/{app_guid}/summary_report"
    params = {}
    if sandbox_guid:
        params["context"] = sandbox_guid
    r = requests.get(url, params=params, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url} failed: {r.status_code}\n{r.text}")
    return safe_get_json(r)


# -------------------------
# PDF generation (wrapped cells + alignment)
# -------------------------

def para(styles, text: Any) -> Paragraph:
    s = "" if text is None else str(text)
    s = s.replace("\n", "<br/>")
    return Paragraph(s, styles["BodyText"])


def make_kv_table(styles, title: str, kv: List[Tuple[str, Any]]) -> List[Any]:
    elems: List[Any] = [Paragraph(f"<b>{title}</b>", styles["Heading3"]), Spacer(1, 6)]
    data = [[para(styles, k), para(styles, v)] for k, v in kv]

    tbl = Table(data, colWidths=[2.2 * inch, 5.3 * inch])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
    ]))
    elems.append(tbl)
    elems.append(Spacer(1, 12))
    return elems


def make_table(styles, title: str, headers: List[str], rows: List[List[Any]], col_widths: List[float]) -> List[Any]:
    elems: List[Any] = [Paragraph(f"<b>{title}</b>", styles["Heading3"]), Spacer(1, 6)]
    data = [[para(styles, h) for h in headers]]
    for r in rows:
        data.append([para(styles, c) for c in r])

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elems.append(tbl)
    elems.append(Spacer(1, 12))
    return elems


def build_pdf(summary: Dict[str, Any], out_pdf: str) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out_pdf, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)

    elems: List[Any] = []
    elems.append(Paragraph("<b>Veracode Summary Report</b>", styles["Title"]))
    elems.append(Spacer(1, 12))

    overview = [
        ("Application", summary.get("app_name")),
        ("App ID", summary.get("app_id")),
        ("Build ID", summary.get("build_id")),
        ("Policy", summary.get("policy_name")),
        ("Policy Status", summary.get("policy_compliance_status")),
        ("Generation Date", summary.get("generation_date")),
        ("Sandbox", summary.get("sandbox_name")),
        ("Is Latest Build", summary.get("is_latest_build")),
    ]
    elems += make_kv_table(styles, "Overview", overview)

    # Flaw status
    fs = summary.get("flaw_status") or {}
    fs_rows = [[k, fs.get(k)] for k in [
        "_new", "reopen", "open", "fixed", "total", "not_mitigated",
        "sev5_change", "sev4_change", "sev3_change", "sev2_change", "sev1_change",
        "conforms_to_guidelines", "deviates_from_guidelines", "total_reviewed_mitigations"
    ] if k in fs]
    if fs_rows:
        elems += make_table(styles, "Flaw Status", ["Metric", "Value"], fs_rows, [3.0 * inch, 4.5 * inch])

    # Severity breakdown
    sev_rows: List[List[Any]] = []
    for level_obj in (summary.get("severity") or []):
        lvl = level_obj.get("level")
        for cat in (level_obj.get("category") or []):
            category = cat.get("categoryname") or cat.get("category_name") or cat.get("categoryName")
            sev_rows.append([lvl, cat.get("severity"), category, cat.get("count")])
    if sev_rows:
        elems += make_table(
            styles,
            "Severity Breakdown",
            ["Level", "Severity", "Category", "Count"],
            sev_rows,
            [0.8 * inch, 1.2 * inch, 4.6 * inch, 0.9 * inch]
        )

    # Module sections (static/dynamic/manual)
    def module_rows(block: Dict[str, Any]) -> List[List[Any]]:
        modules = (((block or {}).get("modules") or {}).get("module") or [])
        out: List[List[Any]] = []
        for m in modules:
            out.append([
                m.get("name"),
                m.get("score"),
                m.get("loc"),
                f"0:{m.get('numflawssev0')} 1:{m.get('numflawssev1')} 2:{m.get('numflawssev2')} "
                f"3:{m.get('numflawssev3')} 4:{m.get('numflawssev4')} 5:{m.get('numflawssev5')}",
                m.get("target_url") or m.get("domain"),
            ])
        return out

    for label, block in [
        ("Static Analysis Modules", summary.get("static_analysis") or {}),
        ("Dynamic Analysis Modules", summary.get("dynamic_analysis") or {}),
        ("Manual Analysis Modules", summary.get("manual_analysis") or {}),
    ]:
        rows = module_rows(block)
        if rows:
            elems += make_table(
                styles,
                label,
                ["Module", "Score", "LOC", "Flaws by Sev", "Target/Domain"],
                rows,
                [2.4 * inch, 0.7 * inch, 0.7 * inch, 2.6 * inch, 1.6 * inch]
            )

    # SCA summary (avoid massive appendices by default)
    sca = summary.get("software_composition_analysis") or {}
    sca_kv = [
        ("SCA available", sca.get("sca_service_available")),
        ("Third-party components", sca.get("third_party_components")),
        ("Violate policy", sca.get("violate_policy")),
        ("Components violated policy", sca.get("components_violated_policy")),
        ("Blacklisted components", sca.get("blacklisted_components")),
    ]
    elems += make_kv_table(styles, "Software Composition Analysis Summary", sca_kv)

    doc.build(elems)


# -------------------------
# Main
# -------------------------

def main() -> None:
    api_base = env("VERACODE_API_BASE", required=True).rstrip("/")
    app_name = env("APPLICATION_NAME", required=True)
    sandbox_name = env("SANDBOX_NAME", required=False)

    os.makedirs("out", exist_ok=True)
    auth = hmac_auth()

    # Resolve app GUID
    apps_resp = app_lookup_by_name(api_base, auth, app_name)
    app_guid, app_obj = resolve_app_guid(api_base, auth, app_name)
    write_json("out/application_lookup.json", app_obj)

    # Resolve sandbox GUID if SANDBOX_NAME provided
    sandbox_guid: Optional[str] = None
    if sandbox_name:
        sb_guid, sb_obj = resolve_sandbox_guid_by_name(api_base, auth, app_guid, sandbox_name)
        sandbox_guid = sb_guid
        write_json("out/sandbox_lookup.json", sb_obj)
        print(f"Resolved sandbox_name='{sandbox_name}' -> sandbox_guid='{sandbox_guid}'")
    else:
        print("SANDBOX_NAME not provided; using policy/prod context (no context param).")

    # Pull summary report JSON
    summary = get_summary_report(api_base, auth, app_guid, sandbox_guid)
    write_json("out/summary_report.json", summary)

    # Generate PDF
    build_pdf(summary, "out/summary_report.pdf")

    print("Wrote out/summary_report.json and out/summary_report.pdf")


if __name__ == "__main__":
    main()

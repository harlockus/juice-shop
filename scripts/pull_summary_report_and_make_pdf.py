#!/usr/bin/env python3
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

API_TIMEOUT_S = 60

def must_env(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        return ""
    return v

def must_env_required(name: str) -> str:
    v = must_env(name)
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v

def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def hmac_auth() -> RequestsAuthPluginVeracodeHMAC:
    api_id = must_env_required("VERACODE_API_ID")
    api_key = must_env_required("VERACODE_API_KEY")
    return RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)

# ---------- Applications API lookup (by name) ----------
def app_lookup(api_base: str, auth, name: str) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications"
    r = requests.get(url, params={"name": name, "page": 0, "size": 50}, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url}?name={name} failed: {r.status_code}\n{r.text}")
    return r.json()

def extract_app_ids(apps_resp: Dict[str, Any]) -> Tuple[int, str, Dict[str, Any]]:
    embedded = apps_resp.get("_embedded") or {}
    apps = embedded.get("applications") or []
    if not apps:
        raise SystemExit("No applications returned. Check APPLICATION_NAME or permissions.")
    app0 = apps[0]
    app_id = int(app0["id"])
    app_guid = app0["guid"]
    return app_id, app_guid, app0

# ---------- Summary Report API ----------
def get_summary_report(api_base: str, auth, app_guid: str, sandbox_guid: str) -> Dict[str, Any]:
    # Endpoint documented here.  [oai_citation:6‡Veracode Docs](https://docs.veracode.com/r/c_sum_report_gen_rest?utm_source=chatgpt.com)
    url = f"{api_base}/appsec/v2/applications/{app_guid}/summary_report"
    params = {}
    if sandbox_guid:
        params["context"] = sandbox_guid
    r = requests.get(url, params=params, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url} failed: {r.status_code}\n{r.text}")
    return r.json()

# ---------- PDF helpers ----------
def p(styles, text: Any) -> Paragraph:
    # Wrap everything safely into a Paragraph (enables wrapping in table cells)
    s = "" if text is None else str(text)
    return Paragraph(s.replace("\n", "<br/>"), styles["BodyText"])

def make_kv_table(styles, title: str, kv: List[Tuple[str, Any]]) -> List[Any]:
    elems = [Paragraph(f"<b>{title}</b>", styles["Heading3"]), Spacer(1, 6)]
    data = [[p(styles, k), p(styles, v)] for k, v in kv]
    tbl = Table(data, colWidths=[2.2*inch, 5.3*inch])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ALIGN", (0,0), (0,-1), "LEFT"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    elems.append(tbl)
    elems.append(Spacer(1, 12))
    return elems

def make_table(styles, title: str, headers: List[str], rows: List[List[Any]], col_widths: List[float]) -> List[Any]:
    elems = [Paragraph(f"<b>{title}</b>", styles["Heading3"]), Spacer(1, 6)]
    data = [[p(styles, h) for h in headers]]
    for r in rows:
        data.append([p(styles, c) for c in r])

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
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

    # High-value header fields (kept compact)
    header_kv = [
        ("Application", summary.get("app_name")),
        ("App ID", summary.get("app_id")),
        ("Build ID", summary.get("build_id")),
        ("Policy", summary.get("policy_name")),
        ("Policy Status", summary.get("policy_compliance_status")),
        ("Generation Date", summary.get("generation_date")),
        ("Is Latest Build", summary.get("is_latest_build")),
        ("Sandbox", summary.get("sandbox_name")),
    ]
    elems += make_kv_table(styles, "Overview", header_kv)

    # Flaw status block
    fs = summary.get("flaw_status") or {}
    flaw_rows = [[k, fs.get(k)] for k in [
        "_new","reopen","open","fixed","total","not_mitigated",
        "sev5_change","sev4_change","sev3_change","sev2_change","sev1_change"
    ] if k in fs]
    elems += make_table(
        styles,
        "Flaw Status",
        headers=["Metric", "Value"],
        rows=flaw_rows,
        col_widths=[3.0*inch, 4.5*inch]
    )

    # Severity by level/category (can be long; keep table wrapped)
    sev = summary.get("severity") or []
    sev_rows = []
    for level_obj in sev:
        level = level_obj.get("level")
        for cat in (level_obj.get("category") or []):
            sev_rows.append([level, cat.get("severity"), cat.get("category_name"), cat.get("count")])
    if sev_rows:
        elems += make_table(
            styles,
            "Severity Breakdown",
            headers=["Level", "Severity", "Category", "Count"],
            rows=sev_rows,
            col_widths=[0.8*inch, 1.2*inch, 4.6*inch, 0.9*inch]
        )

    # Static/Dynamic/Manual module summaries (modules can be many; show module-level counts)
    def module_section(label: str, block: Dict[str, Any]):
        modules = (((block or {}).get("modules") or {}).get("module") or [])
        rows = []
        for m in modules:
            rows.append([
                m.get("name"),
                m.get("score"),
                m.get("loc"),
                f"0:{m.get('numflawssev0')} 1:{m.get('numflawssev1')} 2:{m.get('numflawssev2')} 3:{m.get('numflawssev3')} 4:{m.get('numflawssev4')} 5:{m.get('numflawssev5')}",
                m.get("target_url") or m.get("domain"),
            ])
        if rows:
            elems.extend(make_table(
                styles,
                f"{label} Modules",
                headers=["Module", "Score", "LOC", "Flaws by Sev", "Target/Domain"],
                rows=rows,
                col_widths=[2.4*inch, 0.7*inch, 0.7*inch, 2.6*inch, 1.6*inch]
            ))

    module_section("Static Analysis", summary.get("static_analysis") or {})
    module_section("Dynamic Analysis", summary.get("dynamic_analysis") or {})
    module_section("Manual Analysis", summary.get("manual_analysis") or {})

    # SCA: keep it short by default (components list can be huge)
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

def main():
    api_base = must_env_required("VERACODE_API_BASE").rstrip("/")
    app_name = must_env_required("APPLICATION_NAME")
    sandbox_guid = must_env("SANDBOX_GUID")
    auth = hmac_auth()

    os.makedirs("out", exist_ok=True)

    # Resolve app guid
    apps_resp = app_lookup(api_base, auth, app_name)
    app_id, app_guid, app_obj = extract_app_ids(apps_resp)
    write_json("out/application_lookup.json", app_obj)

    # Pull summary JSON
    summary = get_summary_report(api_base, auth, app_guid, sandbox_guid)
    write_json("out/summary_report.json", summary)

    # Build PDF
    build_pdf(summary, "out/summary_report.pdf")

    print(f"Resolved app_name={app_name}, app_id={app_id}, app_guid={app_guid}")
    print("Wrote out/summary_report.json and out/summary_report.pdf")

if __name__ == "__main__":
    main()

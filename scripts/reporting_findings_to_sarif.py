#!/usr/bin/env python3
"""
Veracode Reporting API findings JSON -> SARIF 2.1.0 for GitHub Code Scanning.

Designed for records like:
- local_path / static_local_path (repo-relative)
- source_file_line (string line number)
- severity (0-5)

GitHub requires each SARIF result to have at least one location.
If a finding has no file+line (common for SCA), we anchor it to a placeholder file.
"""

import argparse
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


SEV_MAP = {
    "5": ("error",   "VERY_HIGH", "9.5"),
    "4": ("error",   "HIGH",      "8.0"),
    "3": ("warning", "MEDIUM",    "5.5"),
    "2": ("note",    "LOW",       "3.0"),
    "1": ("note",    "VERY_LOW",  "1.0"),
    "0": ("note",    "INFO",      "0.1"),
}


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def as_str(x: Any) -> str:
    return "" if x is None else str(x)


def normalize_repo_path(p: str) -> str:
    p = p.replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    return p


def safe_int(x: Any, default: int = 1) -> int:
    try:
        v = int(str(x))
        return v if v >= 1 else default
    except Exception:
        return default


def stable_placeholder_line(rule_id: str, msg: str) -> int:
    h = sha256_text(f"{rule_id}|{msg}")
    return (int(h[:8], 16) % 20000) + 1


def pick_first(item: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="out/findings_single_app_<APP>.json (list)")
    ap.add_argument("--output", required=True, help="Output SARIF")
    ap.add_argument("--placeholder-uri", required=True, help="Repo-relative placeholder file")
    ap.add_argument("--output-stats", required=True, help="Stats JSON output")
    ap.add_argument("--tool-name", default="Veracode Reporting API")
    ap.add_argument("--tool-version", default="")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        raise SystemExit("Expected a JSON list (use out/findings_single_app_*.json).")

    placeholder_uri = normalize_repo_path(args.placeholder_uri)

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    total = 0
    with_location = 0
    with_placeholder = 0
    static_count = 0
    sca_count = 0

    for it in findings:
        if not isinstance(it, dict):
            continue
        total += 1

        scan_type = as_str(it.get("scan_type")).strip()
        if scan_type.lower().startswith("static"):
            static_count += 1
        elif scan_type.upper() == "SCA":
            sca_count += 1

        sev_raw = as_str(it.get("severity")).strip()
        sarif_level, sev_label, gh_sec_score = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN", "0.0"))

        cwe_id = as_str(it.get("cwe_id")).strip()
        category_name = as_str(it.get("category_name")).strip()
        flaw_name = as_str(it.get("flaw_name")).strip()
        finding_id = as_str(it.get("finding_id")).strip()

        # Rule ID: CWE where possible, else hash category
        if cwe_id:
            rule_id = f"CWE-{cwe_id}" if not cwe_id.upper().startswith("CWE-") else cwe_id.upper()
        elif category_name:
            rule_id = f"VERACODE-{sha256_text(category_name)[:10].upper()}"
        else:
            rule_id = "VERACODE-ISSUE"

        rule_name = category_name or flaw_name or rule_id

        # Prefer local_path -> static_local_path (these are repo-relative in your data)
        file_path = pick_first(it, ["local_path", "static_local_path"])
        line = safe_int(it.get("source_file_line"), default=1)

        # Message: include Veracode severity + flaw name + id
        msg = flaw_name or it.get("description") or rule_name
        msg = f"[{sev_label}] {msg}" + (f" (finding_id={finding_id})" if finding_id else "")

        # Ensure GitHub-required location
        if file_path:
            uri = normalize_repo_path(file_path)
            start_line = line
            with_location += 1
        else:
            uri = placeholder_uri
            start_line = stable_placeholder_line(rule_id, msg)
            with_placeholder += 1

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": msg},
                "help": {"text": f"{rule_name}\nSeverity: {sev_label}\nRule: {rule_id}"},
                "properties": {
                    "tags": ["security", "veracode", "reporting-api"],
                    "security-severity": gh_sec_score,
                    "veracode-severity": sev_label,
                    "cwe": cwe_id,
                    "scan_type": scan_type,
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line},
                }
            }],
            "properties": {
                "finding_id": finding_id,
                "veracode_severity": sev_label,
                "scan_type": scan_type,
                "isPlaceholderLocation": (uri == placeholder_uri),
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": args.tool_name,
                    **({"version": args.tool_version} if args.tool_version else {}),
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    stats = {
        "input_findings": total,
        "static_analysis_findings": static_count,
        "sca_findings": sca_count,
        "sarif_results": len(results),
        "sarif_rules": len(rules),
        "results_with_file_location": with_location,
        "results_with_placeholder_location": with_placeholder,
        "placeholder_uri": placeholder_uri,
        "path_fields_used": ["local_path", "static_local_path"],
        "line_field_used": "source_file_line",
    }
    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Wrote SARIF: {args.output} (results={len(results)}, rules={len(rules)})")
    print(f"Wrote stats: {args.output_stats} -> {stats}")


if __name__ == "__main__":
    main()

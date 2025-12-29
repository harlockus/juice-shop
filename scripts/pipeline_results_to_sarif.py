#!/usr/bin/env python3
"""
Veracode Pipeline Scan JSON -> SARIF 2.1.0 for GitHub Code Scanning.

Goals:
- Every result has at least one location (required by GitHub).  [oai_citation:3‡GitHub Docs](https://docs.github.com/en/enterprise-cloud%40latest/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com)
- Stable, unique placeholder line numbers (prevents fingerprint conflicts).
- Provide GitHub security severities via rules[].properties.security-severity (0.0–10.0).  [oai_citation:4‡GitHub Docs](https://docs.github.com/en/enterprise-cloud%40latest/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com)
"""

import argparse
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

# Map Veracode numeric severity -> (SARIF level, label, GitHub security-severity score)
# GitHub expects security-severity as a numeric string 0.0–10.0.  [oai_citation:5‡GitHub Docs](https://docs.github.com/en/enterprise-cloud%40latest/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com)
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

def get_first(obj: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return None

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
    """
    Create a stable line number (>=1) for placeholder findings.
    This avoids many results pointing to the same (file,line) pair.
    """
    h = sha256_text(f"{rule_id}|{msg}")
    # 1..20000
    return (int(h[:8], 16) % 20000) + 1

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--placeholder-uri", required=True)
    ap.add_argument("--output-stats", required=True)
    ap.add_argument("--tool-name", default="Veracode Pipeline Scan")
    ap.add_argument("--tool-version", default="")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings") or data.get("issues") or data.get("results") or []
    if not isinstance(findings, list):
        findings = []

    placeholder_uri = normalize_repo_path(args.placeholder_uri)

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    count_total = 0
    count_file_loc = 0
    count_placeholder_loc = 0

    for item in findings:
        if not isinstance(item, dict):
            continue
        count_total += 1

        sev_raw = as_str(get_first(item, "severity", "severity_level", "severityCode")).strip()
        sarif_level, sev_label, gh_sec_score = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN", "0.0"))

        cwe = get_first(item, "cwe", "cwe_id", "cweId")
        cwe_str = as_str(cwe).strip()
        category = as_str(get_first(item, "category", "categoryname", "category_name")).strip()

        if cwe_str:
            rule_id = cwe_str.upper() if cwe_str.upper().startswith("CWE-") else f"CWE-{cwe_str}"
        elif category:
            rule_id = f"VERACODE-{sha256_text(category)[:10].upper()}"
        else:
            rule_id = "VERACODE-ISSUE"

        rule_name = category or rule_id
        message_text = as_str(get_first(item, "display_text", "message", "description", "issue_type")).strip()
        if not message_text:
            message_text = rule_name

        file_path = as_str(get_first(item, "file_path", "file", "filename", "source_file")).strip()
        line_raw = get_first(item, "line", "line_number", "lineNumber")
        line = safe_int(line_raw, default=1)

        if file_path:
            uri = normalize_repo_path(file_path)
            count_file_loc += 1
        else:
            uri = placeholder_uri
            line = stable_placeholder_line(rule_id, message_text)
            count_placeholder_loc += 1

        # Define rule once with GitHub security severity metadata
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": message_text},
                "help": {"text": f"{rule_name}\nSeverity: {sev_label}\nRule: {rule_id}"},
                "properties": {
                    # Important: tag as security + provide security-severity score.  [oai_citation:6‡GitHub Docs](https://docs.github.com/en/enterprise-cloud%40latest/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com)
                    "tags": ["security", "veracode", "pipeline-scan"],
                    "security-severity": gh_sec_score,
                    "precision": "high",
                    "veracode-severity": sev_label,
                    "cwe": cwe_str,
                },
            }

        # Also prefix message with Veracode severity so it’s visible in titles.
        titled_msg = f"[{sev_label}] {message_text}"

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,  # used by GitHub filters  [oai_citation:7‡GitHub Docs](https://docs.github.com/en/enterprise-cloud%40latest/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com)
            "message": {"text": titled_msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line},
                    }
                }
            ],
            "properties": {
                "veracode-severity": sev_label,
                "isPlaceholderLocation": (uri == placeholder_uri),
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": args.tool_name,
                        **({"version": args.tool_version} if args.tool_version else {}),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    stats = {
        "findings_total_in_json": count_total,
        "sarif_results_written": len(results),
        "sarif_rules_written": len(rules),
        "results_with_file_location": count_file_loc,
        "results_with_placeholder_location": count_placeholder_loc,
        "placeholder_uri": placeholder_uri,
    }
    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Wrote SARIF: {args.output} (results={len(results)}, rules={len(rules)})")
    print(f"Wrote stats: {args.output_stats} -> {stats}")

if __name__ == "__main__":
    main()

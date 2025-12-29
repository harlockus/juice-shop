#!/usr/bin/env python3
"""
Ultimate Veracode Pipeline Scan JSON -> SARIF 2.1.0 converter
for GitHub Code Scanning.

Guarantee: EVERY SARIF result has at least one location (required by GitHub).
If a finding has no file path, it is anchored to a placeholder file in the repo.

Usage:
  python scripts/pipeline_results_to_sarif.py \
    --input results.json \
    --output veracode-pipeline.sarif \
    --placeholder-uri .veracode/PIPELINE_SCAN_GLOBAL_FINDINGS.md \
    --output-stats veracode-pipeline-sarif-stats.json
"""
import argparse
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


SEV_MAP = {
    # Pipeline Scan usually emits 0-4
    "4": ("error", "HIGH"),
    "3": ("warning", "MEDIUM"),
    "2": ("note", "LOW"),
    "1": ("note", "VERY_LOW"),
    "0": ("note", "INFO"),
    # Future-proof:
    "5": ("error", "VERY_HIGH"),
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
    """
    Ensure SARIF artifactLocation.uri is a repo-relative path.
    """
    p = p.replace("\\", "/").strip()
    # remove leading ./ for GitHub UI cleanliness
    if p.startswith("./"):
        p = p[2:]
    return p


def safe_int(x: Any, default: int = 1) -> int:
    try:
        v = int(str(x))
        return v if v >= 1 else default
    except Exception:
        return default


def make_fingerprint(rule_id: str, path: str, line: int, msg: str) -> str:
    return sha256_text(f"{rule_id}|{path}|{line}|{msg}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Pipeline Scan results.json")
    ap.add_argument("--output", required=True, help="Output SARIF file")
    ap.add_argument("--placeholder-uri", required=True, help="Repo-relative file for non-file findings")
    ap.add_argument("--output-stats", required=True, help="Stats JSON output path")
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
        level, sev_label = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN"))

        cwe = get_first(item, "cwe", "cwe_id", "cweId")
        cwe_str = as_str(cwe).strip()
        category = as_str(get_first(item, "category", "categoryname", "category_name")).strip()

        # ruleId: prefer CWE; else deterministic hash of category
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

        # location extraction
        file_path = as_str(get_first(item, "file_path", "file", "filename", "source_file")).strip()
        line_raw = get_first(item, "line", "line_number", "lineNumber")
        line = safe_int(line_raw, default=1)

        if file_path:
            uri = normalize_repo_path(file_path)
            count_file_loc += 1
        else:
            # capture *every* flaw: anchor to placeholder file
            uri = placeholder_uri
            line = 1
            count_placeholder_loc += 1

        # define rule once
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": message_text},
                "help": {
                    "text": (
                        f"{rule_name}\n\n"
                        f"Severity: {sev_label}\n"
                        f"Rule: {rule_id}\n"
                        f"{('CWE: ' + cwe_str + '\\n') if cwe_str else ''}"
                    )
                },
                "properties": {
                    "tags": ["veracode", "pipeline-scan"],
                    "severity": sev_label,
                    "cwe": cwe_str,
                },
            }

        result_obj: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,  # error|warning|note|none
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line},
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": make_fingerprint(rule_id, uri, line, message_text)
            },
            "properties": {
                "severity": sev_label,
                "category": category,
                "source": "veracode-pipeline-scan",
                "isPlaceholderLocation": (uri == placeholder_uri),
            },
        }

        results.append(result_obj)

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
        "note": "GitHub requires at least one location per SARIF result; placeholder used when a finding has no file path.",
    }

    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Wrote SARIF: {args.output} (results={len(results)}, rules={len(rules)})")
    print(f"Wrote stats: {args.output_stats} -> {stats}")


if __name__ == "__main__":
    main()

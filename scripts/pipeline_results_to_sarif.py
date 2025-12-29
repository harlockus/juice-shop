#!/usr/bin/env python3
"""
Convert Veracode Pipeline Scan JSON (results.json) to SARIF 2.1.0.

Goal: show findings in GitHub Security -> Code scanning alerts.

Usage:
  python scripts/pipeline_results_to_sarif.py results.json veracode-pipeline.sarif
"""
import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple


SEV_MAP = {
    # Pipeline Scan typically uses 0-4
    "4": ("error", "HIGH"),
    "3": ("warning", "MEDIUM"),
    "2": ("note", "LOW"),
    "1": ("note", "VERY_LOW"),
    "0": ("note", "INFO"),
    # If present:
    "5": ("error", "VERY_HIGH"),
}


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _as_str(x: Any) -> str:
    return "" if x is None else str(x)


def _get(obj: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return None


def _rel_path(p: str) -> str:
    # Ensure GitHub can map paths inside repo. Keep relative.
    p = p.replace("\\", "/")
    # strip common prefixes
    for prefix in ("/home/runner/work/",):
        if p.startswith(prefix):
            # keep everything after repo root; best-effort
            parts = p.split("/")
            if len(parts) >= 6:
                # /home/runner/work/<repo>/<repo>/...
                return "/".join(parts[5:])
    return p.lstrip("./")


def _fingerprint(rule_id: str, path: str, line: Optional[int], msg: str) -> str:
    base = f"{rule_id}|{path}|{line or ''}|{msg}"
    return _sha256(base)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_json", help="Pipeline Scan results.json")
    ap.add_argument("output_sarif", help="Output SARIF file path")
    ap.add_argument("--tool-name", default="Veracode Pipeline Scan", help="SARIF tool name")
    ap.add_argument("--tool-version", default="", help="Optional tool version")
    args = ap.parse_args()

    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = (
        data.get("findings")
        or data.get("issues")
        or data.get("results")
        or []
    )
    if not isinstance(findings, list):
        findings = []

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for item in findings:
        if not isinstance(item, dict):
            continue

        sev_raw = _as_str(_get(item, "severity", "severity_level", "severityCode"))
        level, sev_label = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN"))

        cwe = _get(item, "cwe", "cwe_id", "cweId")
        cwe_str = _as_str(cwe).strip()
        category = _as_str(_get(item, "category", "categoryname", "category_name")).strip()

        # ruleId: prefer CWE if present; else category hash
        if cwe_str:
            rule_id = f"CWE-{cwe_str}" if not cwe_str.upper().startswith("CWE-") else cwe_str.upper()
        elif category:
            rule_id = f"VERACODE-{_sha256(category)[:8].upper()}"
        else:
            rule_id = "VERACODE-ISSUE"

        rule_name = category or rule_id
        message_text = _as_str(_get(item, "display_text", "message", "description", "issue_type")).strip()
        if not message_text:
            message_text = rule_name

        file_path = _as_str(_get(item, "file_path", "file", "filename", "source_file")).strip()
        file_path = _rel_path(file_path) if file_path else ""

        line = _get(item, "line", "line_number", "lineNumber")
        try:
            start_line = int(line) if line is not None else None
        except Exception:
            start_line = None

        # Add rule definition once
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": message_text},
                "help": {
                    "text": f"{rule_name}\n\nSeverity: {sev_label}\nRule: {rule_id}",
                },
                "properties": {
                    "tags": ["veracode", "sast"],
                    "severity": sev_label,
                    "cwe": cwe_str,
                },
            }

        sarif_result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,  # error|warning|note|none
            "message": {"text": message_text},
            "properties": {
                "severity": sev_label,
                "category": category,
            },
        }

        if file_path:
            loc: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                }
            }
            if start_line and start_line > 0:
                loc["physicalLocation"]["region"] = {"startLine": start_line}
            sarif_result["locations"] = [{"location": loc}]

        # fingerprint helps GitHub correlate recurring alerts
        sarif_result["partialFingerprints"] = {
            "primaryLocationLineHash": _fingerprint(rule_id, file_path, start_line, message_text)
        }

        results.append(sarif_result)

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": args.tool_name,
                        "version": args.tool_version or None,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    # remove null version field if not set
    drv = sarif["runs"][0]["tool"]["driver"]
    if drv.get("version") is None:
        drv.pop("version", None)

    with open(args.output_sarif, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    print(f"Wrote SARIF: {args.output_sarif}  (results={len(results)}, rules={len(rules)})")


if __name__ == "__main__":
    main()

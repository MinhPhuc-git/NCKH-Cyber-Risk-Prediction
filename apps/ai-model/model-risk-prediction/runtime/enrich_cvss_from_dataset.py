#!/usr/bin/env python3
"""Extract CVSS records for a requested CVE set from the local CYRP CTI dataset.

Input on stdin:
    {"cveIds": ["CVE-2024-...", ...]}

Output on stdout:
    JSON containing matched records and scan statistics.

The script deliberately uses only the Python standard library so it can run in
exactly the same virtual environment as the model worker.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null", "unknown", "n/a", "na", "-1"}:
        return None
    return text


def component_value(value: Any) -> str | None:
    """Normalize a CVSS component while preserving the valid value NONE."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "null", "unknown", "n/a", "na", "-1"}:
        return None
    return text.upper()


def vector_components(vector: str | None) -> dict[str, str]:
    if not vector:
        return {}

    tokens: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, separator, value = part.partition(":")
        if separator and key and value:
            tokens[key.upper()] = value.upper()

    is_cvss3 = vector.upper().startswith("CVSS:3.")
    mappings = {
        "attackVector": ("AV", {
            "N": "NETWORK",
            "A": "ADJACENT",
            "L": "LOCAL",
            "P": "PHYSICAL",
        }),
        "attackComplexity": ("AC", {"L": "LOW", "H": "HIGH"}),
        "privilegesRequired": ("PR", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
        "userInteraction": ("UI", {
            "N": "NONE",
            "R": "REQUIRED",
            "P": "PASSIVE",
            "A": "ACTIVE",
        }),
        **({"scope": ("S", {"U": "UNCHANGED", "C": "CHANGED"})} if is_cvss3 else {}),
        "confidentialityImpact": (
            "VC" if "VC" in tokens else "C",
            {"N": "NONE", "L": "LOW", "H": "HIGH"},
        ),
        "integrityImpact": (
            "VI" if "VI" in tokens else "I",
            {"N": "NONE", "L": "LOW", "H": "HIGH"},
        ),
        "availabilityImpact": (
            "VA" if "VA" in tokens else "A",
            {"N": "NONE", "L": "LOW", "H": "HIGH"},
        ),
    }

    result: dict[str, str] = {}
    for field, (token, values) in mappings.items():
        raw_value = tokens.get(token)
        if raw_value is not None:
            result[field] = values.get(raw_value, raw_value)
    return result


def number(value: Any) -> float | None:
    text = clean(value)
    if text is None:
        return None
    try:
        parsed = float(text)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def iso_date(value: Any) -> str | None:
    text = clean(value)
    if text is None:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).isoformat()
    except ValueError:
        return None


def severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def cwe_id(row: dict[str, str]) -> str | None:
    candidates = [
        row.get("CVSS_cwe_id"),
        row.get("MS_CWE"),
        row.get("KEV_cwes"),
    ]
    for candidate in candidates:
        text = clean(candidate)
        if text is None:
            continue
        match = CWE_PATTERN.search(text)
        if match:
            return match.group(0).upper()
    return None


def normalized_record(row: dict[str, str]) -> dict[str, Any] | None:
    cve_id = clean(row.get("CVE_ID"))
    if cve_id is None or not CVE_PATTERN.fullmatch(cve_id):
        return None

    version = clean(row.get("CVSS_cvss_version"))
    vector = clean(row.get("CVSS_vector_string")) or clean(row.get("MS_Vector String"))
    base_score = number(row.get("CVSS_base_score"))

    parsed_components = vector_components(vector)
    components = {
        "attackVector": component_value(row.get("CVSS_attack_vector"))
        or parsed_components.get("attackVector"),
        "attackComplexity": component_value(row.get("CVSS_attack_complexity"))
        or parsed_components.get("attackComplexity"),
        "privilegesRequired": component_value(row.get("CVSS_privileges_required"))
        or parsed_components.get("privilegesRequired"),
        "userInteraction": component_value(row.get("CVSS_user_interaction"))
        or parsed_components.get("userInteraction"),
        "scope": component_value(row.get("CVSS_scope"))
        or parsed_components.get("scope"),
        "confidentialityImpact": component_value(row.get("CVSS_confidentiality"))
        or parsed_components.get("confidentialityImpact"),
        "integrityImpact": component_value(row.get("CVSS_integrity"))
        or parsed_components.get("integrityImpact"),
        "availabilityImpact": component_value(row.get("CVSS_availability"))
        or parsed_components.get("availabilityImpact"),
    }

    if base_score is None and vector is None and not any(components.values()):
        return None

    return {
        "cveId": cve_id.upper(),
        "cvssVersion": version or "UNKNOWN",
        "vectorString": vector,
        "baseScore": base_score,
        "baseSeverity": severity(base_score),
        **components,
        "publishedAt": iso_date(row.get("CVSS_published_date")),
        "modifiedAt": iso_date(row.get("CVSS_last_modified")),
        "description": clean(row.get("CVSS_description")),
        "cweId": cwe_id(row),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    args = parser.parse_args()

    started = time.perf_counter()
    payload = json.load(sys.stdin)
    requested = {
        str(value).strip().upper()
        for value in payload.get("cveIds", [])
        if CVE_PATTERN.fullmatch(str(value).strip())
    }

    dataset = Path(args.dataset).expanduser().resolve()
    if not dataset.is_file():
        raise FileNotFoundError(f"CTI dataset not found: {dataset}")

    records: list[dict[str, Any]] = []
    found_ids: set[str] = set()
    scanned_rows = 0

    if requested:
        with dataset.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                scanned_rows += 1
                cve_id = str(row.get("CVE_ID") or "").strip().upper()
                if cve_id not in requested:
                    continue
                record = normalized_record(row)
                if record is not None and record['cveId'] not in found_ids:
                    records.append(record)
                    found_ids.add(record['cveId'])
                if found_ids >= requested:
                    break

    result = {
        "requested": len(requested),
        "matched": len(records),
        "missing": max(0, len(requested) - len(records)),
        "scannedRows": scanned_rows,
        "durationMs": round((time.perf_counter() - started) * 1000),
        "records": records,
    }
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(
            json.dumps(
                {
                    "error": str(error),
                    "type": error.__class__.__name__,
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )
        raise

import argparse
import csv
import getpass
import json
import re
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def normalize_cve(value):
    if value is None:
        return None

    text = str(value).strip().upper()
    match = CVE_PATTERN.search(text)

    if not match:
        return None

    return match.group(0).upper()


def deep_find_first(obj, candidate_keys):
    candidate_keys = {key.lower() for key in candidate_keys}

    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in candidate_keys and value not in (None, ""):
                return value

        for value in obj.values():
            found = deep_find_first(value, candidate_keys)
            if found not in (None, ""):
                return found

    elif isinstance(obj, list):
        for item in obj:
            found = deep_find_first(item, candidate_keys)
            if found not in (None, ""):
                return found

    return None


def deep_find_cve(obj):
    direct = deep_find_first(
        obj,
        {
            "cve",
            "cve_id",
            "cveId",
            "id",
            "name",
            "vulnerability.id",
            "vulnerability.cve",
        },
    )

    cve = normalize_cve(direct)
    if cve:
        return cve

    if isinstance(obj, dict):
        for value in obj.values():
            found = deep_find_cve(value)
            if found:
                return found

    elif isinstance(obj, list):
        for item in obj:
            found = deep_find_cve(item)
            if found:
                return found

    return None


def extract_agent_id(source):
    value = deep_find_first(
        source,
        {
            "agent_id",
            "agent.id",
            "id",
        },
    )

    # Ưu tiên source.agent.id nếu có
    if isinstance(source, dict):
        agent = source.get("agent")
        if isinstance(agent, dict):
            agent_id = agent.get("id")
            if agent_id not in (None, ""):
                return str(agent_id).strip()

    if value in (None, ""):
        return ""

    return str(value).strip()


def build_query(agent_id=None, size=1000):
    must = []

    if agent_id:
        must.append({"term": {"agent.id": str(agent_id)}})

    query = {
        "size": size,
        "_source": True,
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}],
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"exists": {"field": "vulnerability.id"}},
                                {"exists": {"field": "vulnerability.cve"}},
                                {"exists": {"field": "cve"}},
                                {"exists": {"field": "cve_id"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                ],
            }
        },
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ],
    }

    return query


def fetch_with_search_after(indexer_url, username, password, index_pattern, agent_id=None, size=1000, insecure=True):
    url = f"{indexer_url.rstrip('/')}/{index_pattern}/_search"
    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    session.verify = not insecure
    session.headers.update({"Content-Type": "application/json"})

    all_sources = []
    search_after = None

    while True:
        body = build_query(agent_id=agent_id, size=size)

        if search_after:
            body["search_after"] = search_after

        response = session.post(url, data=json.dumps(body), timeout=60)

        if response.status_code >= 400:
            print("[!] Wazuh Indexer query failed.")
            print(f"Status: {response.status_code}")
            print(response.text[:2000])
            response.raise_for_status()

        payload = response.json()
        hits = payload.get("hits", {}).get("hits", [])

        if not hits:
            break

        for hit in hits:
            source = hit.get("_source", {})
            all_sources.append(source)

        search_after = hits[-1].get("sort")

        if not search_after or len(hits) < size:
            break

    return all_sources



def normalize_pair(cve_id, agent_id):
    cve = normalize_cve(cve_id)
    if not cve:
        return None
    return (cve, str(agent_id or "").strip())


def parse_iso_datetime(value):
    if value in (None, ""):
        return None

    text = str(value).strip()
    if not text:
        return None

    # Hỗ trợ PostgreSQL timestamp, ISO string, và ISO có Z.
    text = text.replace("Z", "+00:00")

    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def read_existing_pairs(path):
    """
    Đọc snapshot từ DB, tối thiểu gồm CVE_ID, agent_id.
    Các cột optional:
      - status
      - last_processed_at / predicted_at / last_seen_at / updated_at
    """
    result = {}

    if not path:
        return result

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Không tìm thấy existing-pairs CSV: {p}")

    with p.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("CVE_ID") or row.get("cve_id") or row.get("cve") or row.get("cveId")
            agent_id = row.get("agent_id") or row.get("agent.id") or row.get("wazuh_agent_id") or row.get("wazuhAgentId")
            key = normalize_pair(cve_id, agent_id)
            if not key:
                continue

            last_processed_raw = (
                row.get("last_processed_at")
                or row.get("predicted_at")
                or row.get("predictedAt")
                or row.get("last_seen_at")
                or row.get("lastSeenAt")
                or row.get("updated_at")
                or row.get("updatedAt")
                or row.get("first_seen_at")
                or row.get("firstSeenAt")
            )

            result[key] = {
                "CVE_ID": key[0],
                "agent_id": key[1],
                "status": (row.get("status") or "").strip().upper(),
                "last_processed_at": last_processed_raw or "",
                "last_processed_dt": parse_iso_datetime(last_processed_raw),
                "raw": row,
            }

    return result


def unique_wazuh_pairs(rows):
    pairs = {}
    for row in rows:
        key = normalize_pair(row.get("CVE_ID"), row.get("agent_id"))
        if not key:
            continue
        pairs[key] = {"CVE_ID": key[0], "agent_id": key[1]}
    return pairs


def days_since(dt, now):
    if dt is None:
        return None
    try:
        return (now - dt).total_seconds() / 86400
    except Exception:
        return None


def classify_lifecycle_delta(
    wazuh_rows,
    existing_pairs,
    stale_days=7,
    force_rescan_days=30,
):
    """
    Phân loại CVE-agent theo CVE_LIFECYCLE_DESIGN.md:
      - new: có ở Wazuh, chưa có trong DB
      - stale: có cả hai bên nhưng last_processed >= stale_days
      - fresh: có cả hai bên và còn mới
      - resolved/missing: có trong DB active snapshot nhưng không còn ở Wazuh scan hiện tại

    Không tự quyết định DB status tại đây; hàm này chỉ xuất CSV delta.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    wazuh_pairs = unique_wazuh_pairs(wazuh_rows)

    wazuh_keys = set(wazuh_pairs.keys())
    existing_keys = set(existing_pairs.keys())

    new_keys = sorted(wazuh_keys - existing_keys, key=lambda x: (x[1], x[0]))
    common_keys = sorted(wazuh_keys & existing_keys, key=lambda x: (x[1], x[0]))
    disappeared_keys = sorted(existing_keys - wazuh_keys, key=lambda x: (x[1], x[0]))

    stale_keys = []
    force_rescan_keys = []
    fresh_keys = []

    for key in common_keys:
        record = existing_pairs.get(key, {})
        age_days = days_since(record.get("last_processed_dt"), now)

        if age_days is None:
            stale_keys.append(key)
        elif age_days >= force_rescan_days:
            force_rescan_keys.append(key)
        elif age_days >= stale_days:
            stale_keys.append(key)
        else:
            fresh_keys.append(key)

    process_keys = sorted(
        set(new_keys) | set(stale_keys) | set(force_rescan_keys),
        key=lambda x: (x[1], x[0]),
    )

    def rows_from_keys(keys):
        return [{"CVE_ID": key[0], "agent_id": key[1]} for key in keys]

    return {
        "wazuh_pairs": wazuh_pairs,
        "existing_pairs": existing_pairs,
        "new": rows_from_keys(new_keys),
        "stale": rows_from_keys(stale_keys),
        "force_rescan": rows_from_keys(force_rescan_keys),
        "fresh": rows_from_keys(fresh_keys),
        "resolved": rows_from_keys(disappeared_keys),
        "process": rows_from_keys(process_keys),
        "summary": {
            "total_from_wazuh": len(wazuh_keys),
            "total_existing_in_system": len(existing_keys),
            "new_cves": len(new_keys),
            "known_fresh_skipped": len(fresh_keys),
            "known_stale_rescanned": len(stale_keys),
            "force_rescanned": len(force_rescan_keys),
            "missing_from_wazuh": len(disappeared_keys),
            "actually_processed": len(process_keys),
            "skipped": len(fresh_keys),
            "skip_ratio": (
                f"{(len(fresh_keys) / len(wazuh_keys) * 100):.1f}%"
                if wazuh_keys else "0.0%"
            ),
        },
    }


def write_pairs_csv(rows, out_path, write_compat=False):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows = sorted(
        [
            {
                "CVE_ID": (row.get("CVE_ID") or "").strip().upper(),
                "agent_id": (row.get("agent_id") or "").strip(),
            }
            for row in rows
            if (row.get("CVE_ID") or "").strip().upper().startswith("CVE-")
        ],
        key=lambda x: (x["agent_id"], x["CVE_ID"]),
    )

    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["CVE_ID", "agent_id"])
        writer.writeheader()
        writer.writerows(rows)

    if write_compat:
        compat_path = out_path.parent / "List_CVE_ID.csv"
        if compat_path != out_path:
            with compat_path.open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["CVE_ID", "agent_id"])
                writer.writeheader()
                writer.writerows(rows)

    return rows


def write_scan_summary(summary, out_path, extra=None):
    from datetime import datetime, timezone

    if not out_path:
        return None

    payload = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "categories": {
            "new_cves_processed": {
                "count": summary.get("new_cves", 0),
                "action": "process_full_pipeline",
            },
            "known_fresh_skipped": {
                "count": summary.get("known_fresh_skipped", 0),
                "action": "skip_prediction_timestamp_only",
            },
            "known_stale_rescanned": {
                "count": summary.get("known_stale_rescanned", 0),
                "action": "re_predict",
            },
            "force_rescanned": {
                "count": summary.get("force_rescanned", 0),
                "action": "force_re_predict",
            },
            "missing_from_wazuh": {
                "count": summary.get("missing_from_wazuh", 0),
                "action": "write_resolved_or_missing_pairs_for_backend",
            },
        },
        "performance": {
            "actually_processed": summary.get("actually_processed", 0),
            "skipped": summary.get("skipped", 0),
            "skip_ratio": summary.get("skip_ratio", "0.0%"),
        },
        "raw_counts": summary,
    }

    if extra:
        payload["extra"] = extra

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def write_list_cve(rows, out_path):
    return write_pairs_csv(rows, out_path, write_compat=True)

def main():
    parser = argparse.ArgumentParser(
        description="Extract CVE_ID and agent_id from Wazuh Indexer vulnerabilities into LIST_CVE_ID.csv"
    )

    parser.add_argument(
        "--indexer-url",
        default="https://127.0.0.1:19201",
        help="Wazuh Indexer URL, default: https://127.0.0.1:19201",
    )

    parser.add_argument(
        "--index-pattern",
        default="wazuh-states-vulnerabilities-*",
        help="Wazuh vulnerability index pattern",
    )

    parser.add_argument(
        "--username",
        default="admin",
        help="Wazuh Indexer username",
    )

    parser.add_argument(
        "--password",
        default=None,
        help="Wazuh Indexer password. If omitted, prompt securely.",
    )

    parser.add_argument(
        "--agent-id",
        default=None,
        help="Optional Wazuh agent id filter, e.g. 007",
    )

    parser.add_argument(
        "--out",
        default=None,
        help="Output CSV path. Default: CTI Collector/cve_data/LIST_CVE_ID.csv",
    )

    parser.add_argument(
        "--size",
        type=int,
        default=1000,
        help="Batch size for Wazuh Indexer search",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification",
    )


    parser.add_argument(
        "--existing-pairs",
        default=None,
        help="CSV snapshot từ DB gồm CVE_ID,agent_id,status,last_processed_at để scan delta.",
    )

    parser.add_argument(
        "--new-only",
        action="store_true",
        help="Chỉ ghi CVE-agent cần xử lý: CVE mới + CVE stale/force-rescan. Bỏ qua CVE đã biết còn mới.",
    )

    parser.add_argument(
        "--stale-days",
        type=int,
        default=7,
        help="Số ngày sau lần predict gần nhất để re-scan CVE đã biết. Mặc định 7.",
    )

    parser.add_argument(
        "--force-rescan-days",
        type=int,
        default=30,
        help="Số ngày bắt buộc re-scan dù không đổi trạng thái. Mặc định 30.",
    )

    parser.add_argument(
        "--resolved-out",
        default=None,
        help="CSV output cho CVE-agent có trong DB nhưng không còn trong Wazuh scan hiện tại.",
    )

    parser.add_argument(
        "--fresh-out",
        default=None,
        help="CSV output cho CVE-agent có cả hai bên và còn mới nên skip prediction.",
    )

    parser.add_argument(
        "--stale-out",
        default=None,
        help="CSV output cho CVE-agent có cả hai bên nhưng đã stale nên cần re-predict.",
    )

    parser.add_argument(
        "--scan-summary-out",
        default=None,
        help="JSON scan summary để audit delta scan.",
    )


    args = parser.parse_args()

    current_dir = Path(__file__).resolve().parent
    default_out = current_dir / "cve_data" / "LIST_CVE_ID.csv"
    out_path = Path(args.out) if args.out else default_out

    password = args.password
    if password is None:
        password = getpass.getpass(f"Password for Wazuh Indexer user '{args.username}': ")

    print("[*] Query Wazuh Indexer vulnerabilities")
    print(f"    URL: {args.indexer_url}")
    print(f"    Index: {args.index_pattern}")
    print(f"    Agent filter: {args.agent_id or 'ALL'}")
    print(f"    Output: {out_path}")

    sources = fetch_with_search_after(
        indexer_url=args.indexer_url,
        username=args.username,
        password=password,
        index_pattern=args.index_pattern,
        agent_id=args.agent_id,
        size=args.size,
        insecure=args.insecure,
    )

    rows = []

    for source in sources:
        cve_id = deep_find_cve(source)
        agent_id = ""

        if isinstance(source, dict):
            agent = source.get("agent")
            if isinstance(agent, dict):
                agent_id = str(agent.get("id") or "").strip()

        if not agent_id:
            agent_id = str(deep_find_first(source, {"agent_id", "wazuh_agent_id"}) or "").strip()

        if cve_id:
            rows.append({"CVE_ID": cve_id, "agent_id": agent_id})

    if args.existing_pairs:
        existing_pairs = read_existing_pairs(args.existing_pairs)
        delta = classify_lifecycle_delta(
            rows,
            existing_pairs,
            stale_days=args.stale_days,
            force_rescan_days=args.force_rescan_days,
        )

        output_rows = delta["process"] if args.new_only else list(delta["wazuh_pairs"].values())

        written = write_list_cve(output_rows, out_path)

        if args.resolved_out:
            write_pairs_csv(delta["resolved"], args.resolved_out, write_compat=False)
        if args.fresh_out:
            write_pairs_csv(delta["fresh"], args.fresh_out, write_compat=False)
        if args.stale_out:
            combined_stale = delta["stale"] + delta["force_rescan"]
            write_pairs_csv(combined_stale, args.stale_out, write_compat=False)
        if args.scan_summary_out:
            write_scan_summary(
                delta["summary"],
                args.scan_summary_out,
                extra={
                    "mode": "delta" if args.new_only else "full_wazuh_output_with_delta_report",
                    "existing_pairs": str(args.existing_pairs),
                    "resolved_out": str(args.resolved_out or ""),
                    "fresh_out": str(args.fresh_out or ""),
                    "stale_out": str(args.stale_out or ""),
                },
            )

        print(f"[*] Documents read: {len(sources)}")
        print(f"[*] Wazuh current CVE-agent pairs: {delta['summary']['total_from_wazuh']}")
        print(f"[*] System existing CVE-agent pairs: {delta['summary']['total_existing_in_system']}")
        print(f"[*] New CVE-agent rows: {delta['summary']['new_cves']}")
        print(f"[*] Existing fresh skipped: {delta['summary']['known_fresh_skipped']}")
        print(f"[*] Existing stale rescanned: {delta['summary']['known_stale_rescanned']}")
        print(f"[*] Force rescanned: {delta['summary']['force_rescanned']}")
        print(f"[*] Missing from Wazuh / resolved candidates: {delta['summary']['missing_from_wazuh']}")
        print(f"[*] CVE-agent rows written to LIST_CVE_ID.csv: {len(written)}")
        print(f"[*] Saved: {out_path}")
    else:
        written = write_list_cve(rows, out_path)

        print(f"[*] Documents read: {len(sources)}")
        print(f"[*] CVE-agent rows written: {len(written)}")
        print(f"[*] Saved: {out_path}")

    compat_path = out_path.parent / "List_CVE_ID.csv"
    print(f"[*] Saved compatibility copy: {compat_path}")

    if not written:
        print("[i] LIST_CVE_ID.csv không có CVE cần xử lý. Đây là bình thường nếu delta scan chỉ có CVE đã biết còn mới.")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
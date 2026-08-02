from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-strict-db-delta-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1) Fix read_existing_pairs(): store both raw last_processed_at and parsed last_processed_dt.
pattern = r'''existing\[\(cve_id,\s*agent_id\)\]\s*=\s*\{\s*
\s*"status":\s*\(row\.get\("status"\)\s*or\s*""\)\.strip\(\)\.upper\(\),\s*
\s*"last_processed_at":\s*\(\s*
\s*row\.get\("last_processed_at"\)\s*
\s*or\s*row\.get\("predicted_at"\)\s*
\s*or\s*row\.get\("last_seen_at"\)\s*
\s*or\s*""\s*
\s*\)\.strip\(\),\s*
\s*\}'''

replacement = '''last_processed_at = (
            row.get("last_processed_at")
            or row.get("predicted_at")
            or row.get("last_seen_at")
            or ""
        ).strip()

        existing[(cve_id, agent_id)] = {
            "status": (row.get("status") or "").strip().upper(),
            "last_processed_at": last_processed_at,
            "last_processed_dt": parse_last_processed_at(last_processed_at),
        }'''

new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)

if count == 0:
    print("[WARN] Không match block existing[...] cũ. Sẽ vá bằng fallback đơn giản.")
    new_text = text.replace(
        '''        existing[(cve_id, agent_id)] = {
            "status": (row.get("status") or "").strip().upper(),
            "last_processed_at": (
                row.get("last_processed_at")
                or row.get("predicted_at")
                or row.get("last_seen_at")
                or ""
            ).strip(),
        }''',
        '''        last_processed_at = (
            row.get("last_processed_at")
            or row.get("predicted_at")
            or row.get("last_seen_at")
            or ""
        ).strip()

        existing[(cve_id, agent_id)] = {
            "status": (row.get("status") or "").strip().upper(),
            "last_processed_at": last_processed_at,
            "last_processed_dt": parse_last_processed_at(last_processed_at),
        }'''
    )

text = new_text

# 2) Make classify_lifecycle_delta robust: fallback parse last_processed_at if last_processed_dt is missing.
text = text.replace(
    '''        age_days = days_since(record.get("last_processed_dt"), now)''',
    '''        last_processed_dt = record.get("last_processed_dt") or parse_last_processed_at(record.get("last_processed_at"))
        age_days = days_since(last_processed_dt, now)'''
)

# 3) Force strict new-only behavior: with --new-only, only truly new CVE-agent pairs are written.
text = text.replace(
    '''        output_rows = delta["process"] if args.new_only else list(delta["wazuh_pairs"].values())''',
    '''        if args.new_only:
            # Strict optimization mode:
            # LIST_CVE_ID.csv is only a queue for CVE-agent pairs that are not already in DB.
            # Existing CVE-agent pairs are skipped completely to avoid repeated model execution.
            output_rows = delta["new"]
        else:
            output_rows = list(delta["wazuh_pairs"].values())'''
)

# 4) Update summary in strict new-only mode so logs are not misleading.
text = text.replace(
    '''        print(f"[*] Existing stale rescanned: {delta['summary']['known_stale_rescanned']}")''',
    '''        if args.new_only:
            print("[*] Existing stale rescanned: 0")
        else:
            print(f"[*] Existing stale rescanned: {delta['summary']['known_stale_rescanned']}")'''
)

text = text.replace(
    '''        print(f"[*] Existing fresh skipped: {delta['summary']['known_fresh_skipped']}")''',
    '''        if args.new_only:
            strict_skipped = delta['summary']['known_fresh_skipped'] + delta['summary']['known_stale_rescanned'] + delta['summary']['force_rescanned']
            print(f"[*] Existing skipped by DB match: {strict_skipped}")
        else:
            print(f"[*] Existing fresh skipped: {delta['summary']['known_fresh_skipped']}")'''
)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

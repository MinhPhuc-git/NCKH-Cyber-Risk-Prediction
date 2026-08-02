from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-force-new-only-skip-existing-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# Add an explicit CLI flag if not already present.
if "--skip-existing-always" not in text:
    marker = 'parser.add_argument(\n        "--new-only",'
    if marker in text:
        insert_pos = text.find(marker)
        # Put the new flag before --new-only.
        flag = '''parser.add_argument(
        "--skip-existing-always",
        action="store_true",
        help="When using --existing-pairs, skip every CVE-agent already present in the system DB. Only truly new CVE-agent pairs are written to LIST_CVE_ID.csv.",
    )

    '''
        text = text[:insert_pos] + flag + text[insert_pos:]

# Force this flag ON when --new-only is used, matching the thesis optimization requirement.
main_marker = "args = parser.parse_args()"
if main_marker in text and "args.skip_existing_always = True" not in text:
    text = text.replace(
        main_marker,
        main_marker + '''
    if getattr(args, "new_only", False):
        args.skip_existing_always = True
''',
        1,
    )

# Patch the classification block robustly:
# Any branch that sees an existing record should treat it as fresh/skip when skip_existing_always is enabled.
patterns = [
    (
        r"if\s+is_stale_record\(([^)]*)\):\s*\n(\s*)stale_rows\.append\(([^)]*)\)\s*\n(\s*)else:\s*\n(\s*)fresh_rows\.append\(([^)]*)\)",
        r"if getattr(args, 'skip_existing_always', False):\n\2fresh_rows.append(\6)\n\2elif is_stale_record(\1):\n\2stale_rows.append(\3)\n\4else:\n\5fresh_rows.append(\6)",
    ),
    (
        r"if\s+([^:\n]*days_since[^:\n]*>=\s*args\.stale_days[^:\n]*):\s*\n(\s*)stale_rows\.append\(([^)]*)\)\s*\n(\s*)else:\s*\n(\s*)fresh_rows\.append\(([^)]*)\)",
        r"if getattr(args, 'skip_existing_always', False):\n\2fresh_rows.append(\6)\n\2elif \1:\n\2stale_rows.append(\3)\n\4else:\n\5fresh_rows.append(\6)",
    ),
    (
        r"if\s+([^:\n]*last_processed[^:\n]*):\s*\n(\s*)stale_rows\.append\(([^)]*)\)\s*\n(\s*)else:\s*\n(\s*)fresh_rows\.append\(([^)]*)\)",
        r"if getattr(args, 'skip_existing_always', False):\n\2fresh_rows.append(\6)\n\2elif \1:\n\2stale_rows.append(\3)\n\4else:\n\5fresh_rows.append(\6)",
    ),
]

for pattern, replacement in patterns:
    text = re.sub(pattern, replacement, text)

# Last-resort patch: after existing/stale/fresh rows are computed but before write_list_cve(),
# remove any CVE-agent that already exists in existing_pairs when new_only is enabled.
needle = "written = write_list_cve("
if needle in text and "FORCE NEW-ONLY FILTER" not in text:
    idx = text.find(needle)
    line_start = text.rfind("\n", 0, idx) + 1
    indent = text[line_start:idx]

    guard = f'''{indent}# FORCE NEW-ONLY FILTER: in optimized delta mode, never reprocess CVE-agent pairs already present in DB.
{indent}if getattr(args, "new_only", False) and existing_pairs:
{indent}    existing_keys_for_filter = set(existing_pairs.keys()) if hasattr(existing_pairs, "keys") else set(existing_pairs)
{indent}    rows = [
{indent}        row for row in rows
{indent}        if (
{indent}            normalize_cve(row.get("CVE_ID") or row.get("cve_id") or row.get("cve"))
{indent}            ,
{indent}            str(row.get("agent_id") or row.get("wazuh_agent_id") or row.get("agent.id") or "").strip()
{indent}        ) not in existing_keys_for_filter
{indent}    ]

'''
    text = text[:line_start] + guard + text[line_start:]

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

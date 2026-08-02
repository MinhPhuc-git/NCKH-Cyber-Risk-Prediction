from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\ai-model\model-risk-prediction\CTI Collector\Extract_Data_Wazuh.py")

backup = path.with_suffix(".py.bak-fix-stale-date-parse-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1) Ensure datetime imports.
if "from datetime import datetime, timezone" not in text:
    if "from datetime import datetime" in text:
        text = text.replace(
            "from datetime import datetime",
            "from datetime import datetime, timezone",
            1,
        )
    else:
        # Insert after normal imports.
        text = text.replace(
            "import sys\n",
            "import sys\nfrom datetime import datetime, timezone\n",
            1,
        )

helper = r'''
def parse_last_processed_at(value):
    value = (value or "").strip()

    if not value:
        return None

    candidates = []
    normalized = value

    # PostgreSQL sometimes exports '+00' instead of '+00:00'
    if re.search(r"[+-]\d{2}$", normalized):
        normalized = normalized + ":00"

    # PostgreSQL timestamp format: "2026-07-28 10:07:09.19+00:00"
    candidates.append(normalized.replace(" ", "T", 1))

    # ISO Z format: "2026-07-28T11:45:06.570Z"
    candidates.append(normalized.replace("Z", "+00:00"))

    # Raw fallback
    candidates.append(normalized)

    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def is_stale_record(last_processed_at, stale_days):
    parsed = parse_last_processed_at(last_processed_at)

    if parsed is None:
        return True

    now = datetime.now(timezone.utc)
    age_days = (now - parsed).total_seconds() / 86400

    return age_days >= stale_days
'''

if "def parse_last_processed_at(" not in text:
    # Put helper before read_existing_pairs if available.
    marker = "def read_existing_pairs("
    if marker in text:
        text = text.replace(marker, helper + "\n" + marker, 1)
    else:
        text = text + "\n" + helper + "\n"

# 2) Replace stale checks that likely use date/days logic.
# This handles common generated patterns.
text = re.sub(
    r"days_since\s*>=\s*args\.stale_days",
    "is_stale_record(record.get('last_processed_at'), args.stale_days)",
    text,
)

text = re.sub(
    r"days_since\s*>=\s*stale_days",
    "is_stale_record(record.get('last_processed_at'), stale_days)",
    text,
)

# 3) Stronger targeted patch: find conditions involving last_processed_at and stale_days.
text = re.sub(
    r"if\s+not\s+last_processed_at\s+or\s+[^:\n]*>=\s*args\.stale_days\s*:",
    "if is_stale_record(last_processed_at, args.stale_days):",
    text,
)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

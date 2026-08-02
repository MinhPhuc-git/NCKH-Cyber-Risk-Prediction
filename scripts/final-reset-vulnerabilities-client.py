from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\vulnerabilities\vulnerabilities-client.tsx")
backup = path.with_suffix(".tsx.bak-final-reset-vulnerabilities-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# Remove AI risk helper block wrongly inserted into Vulnerable detection page.
start_marker = "\nfunction normalizedAiRiskLevel"
end_marker = "\nfunction formatDate"

start = text.find(start_marker)
end = text.find(end_marker)

if start != -1 and end != -1 and end > start:
    text = text[:start] + text[end:]

# Force state: severity + status.
text = text.replace(
    "const [riskLevel, setRiskLevel] = useState('');",
    "const [severity, setSeverity] = useState('');\n  const [status, setStatus] = useState('ACTIVE');",
)

if "const [severity, setSeverity] = useState('');" not in text:
    marker = "const [query, setQuery] = useState('');"
    text = text.replace(
        marker,
        marker + "\n  const [severity, setSeverity] = useState('');\n  const [status, setStatus] = useState('ACTIVE');",
    )

# Force query params.
text = text.replace(
    "if (riskLevel) params.set('riskLevel', riskLevel);",
    "if (severity) params.set('severity', severity);",
)

text = text.replace(
    "params.set('status', 'ACTIVE');",
    "if (status) params.set('status', status);",
)

text = text.replace(
    "}, [page, query, riskLevel]);",
    "}, [page, query, severity, status]);",
)

# Remove local AI filter setData block if present.
text = text.replace(
    "const filteredItems = sortAndFilterByAiRiskLevel(payload.items ?? [], riskLevel);",
    ""
)

text = text.replace(
"""setData({
        ...payload,
        items: filteredItems,
        total: riskLevel ? filteredItems.length : payload.total,
      });""",
    "setData(payload);"
)

# Replace every select block that still uses value={riskLevel}.
replacement = """<select
          className={styles.select}
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo severity"
        >
          <option value="">Mọi severity</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          className={styles.select}
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo trạng thái Wazuh"
        >
          <option value="ACTIVE">Active</option>
          <option value="RESOLVED">Resolved</option>
          <option value="UNDER_EVALUATION">Under evaluation</option>
          <option value="">Tất cả trạng thái</option>
        </select>"""

while "value={riskLevel}" in text:
    idx = text.find("value={riskLevel}")
    select_start = text.rfind("<select", 0, idx)
    select_end = text.find("</select>", idx)

    if select_start == -1 or select_end == -1:
        raise RuntimeError("Found value={riskLevel}, but could not locate enclosing <select> block.")

    select_end += len("</select>")
    text = text[:select_start] + replacement + text[select_end:]

bad_tokens = [
    "value={riskLevel}",
    "setRiskLevel",
    "Mọi risk level",
    "params.set('riskLevel'",
    "sortAndFilterByAiRiskLevel",
    "normalizedAiRiskLevel",
]

remaining = [token for token in bad_tokens if token in text]

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

if remaining:
    print("Still remaining:", remaining)
    raise SystemExit(1)
else:
    print("OK: Vulnerable detection no longer contains AI risk-level filter.")

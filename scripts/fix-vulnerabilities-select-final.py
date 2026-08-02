from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\vulnerabilities\vulnerabilities-client.tsx")
backup = path.with_suffix(".tsx.bak-vuln-select-final-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Ensure state is severity/status, not riskLevel.
text = text.replace(
    "const [riskLevel, setRiskLevel] = useState('');",
    "const [severity, setSeverity] = useState('');\n  const [status, setStatus] = useState('ACTIVE');",
)

if "const [severity, setSeverity] = useState('');" not in text:
    text = text.replace(
        "const [query, setQuery] = useState('');",
        "const [query, setQuery] = useState('');\n  const [severity, setSeverity] = useState('');\n  const [status, setStatus] = useState('ACTIVE');",
    )

# 2. Query params for Wazuh page must use severity/status.
text = text.replace(
    "if (riskLevel) params.set('riskLevel', riskLevel);",
    "if (severity) params.set('severity', severity);",
)

text = text.replace(
    "params.set('status', 'ACTIVE');",
    "if (status) params.set('status', status);",
)

# 3. Remove local AI risk filtering from Wazuh vulnerability page.
text = re.sub(
    r"\s*const filteredItems = sortAndFilterByAiRiskLevel\(payload\.items \?\? \[\], riskLevel\);\s*setData\(\{\s*\.\.\.payload,\s*items: filteredItems,\s*total: riskLevel \? filteredItems\.length : payload\.total,\s*\}\);",
    "\n      setData(payload);",
    text,
    flags=re.S,
)

# 4. Dependency list.
text = text.replace(
    "}, [page, query, riskLevel]);",
    "}, [page, query, severity, status]);",
)

# 5. Replace the select using riskLevel with severity + Wazuh status selects.
text = re.sub(
    r"""
\s*<select
\s+className=\{styles\.select\}
\s+value=\{riskLevel\}
\s+onChange=\{\(event\) => \{
\s+setRiskLevel\(event\.target\.value\);
\s+setPage\(1\);
\s+\}\}
\s+aria-label="Lọc theo risk level AI"
\s*>
\s*<option value="">Mọi risk level</option>
\s*<option value="CRITICAL">Critical</option>
\s*<option value="HIGH">High</option>
\s*<option value="MEDIUM">Medium</option>
\s*<option value="LOW">Low</option>
\s*</select>
""",
    """
        <select
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
        </select>
""",
    text,
    flags=re.S | re.X,
)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\vulnerabilities\vulnerabilities-client.tsx")
backup = path.with_suffix(".tsx.bak-force-vuln-filter-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Bảo đảm state đúng là severity/status.
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

# 2. Bảo đảm query gửi đúng severity/status.
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

# 3. Cắt chính xác select đang chứa value={riskLevel}.
needle = "value={riskLevel}"
idx = text.find(needle)

if idx == -1:
    print("Không còn value={riskLevel}; bỏ qua phần thay select.")
else:
    start = text.rfind("<select", 0, idx)
    end = text.find("</select>", idx)

    if start == -1 or end == -1:
        raise RuntimeError("Tìm thấy value={riskLevel} nhưng không tìm được cặp <select>...</select>.")

    end = end + len("</select>")

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

    text = text[:start] + replacement + text[end:]

# 4. Xóa các dòng lọc local theo AI risk còn sót nếu có.
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

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

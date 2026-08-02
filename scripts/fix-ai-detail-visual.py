from pathlib import Path
from datetime import datetime
import shutil
import re

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-ai-detail-visual-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Bỏ class severity khỏi ô Percentile để nó không còn nền/viền vàng theoutf-8")

# 1. Bỏ class severity khỏi ô Percentile để nó không còn nền/viền vàng theo risk level.
text = text.replace(
"""        <MetricCard
          label="Percentile"
          value={formatPercent(percentile)}
          hint="Percentile AI_CYRP của lỗ hổng này"
          className={severityClass(riskLevel)}
        />
""",
"""        <MetricCard
          label="Percentile"
          value={formatPercent(percentile)}
          hint="Percentile AI_CYRP của lỗ hổng này"
        />
"""
)

# 2. Đổi phần Thiết bị và package từ deviceGrid sang keyValueList để có dấu ":" và cách đều.
old_block = """          <div className={styles.deviceGrid}>
            <div className={styles.deviceInfoCard}><span>Hostname</span><strong>{hostname}</strong></div>
            <div className={styles.deviceInfoCard}><span>Operating system</span><strong>{operatingSystem}</strong></div>
            <div className={styles.deviceInfoCard}><span>Wazuh Agent</span><strong>{wazuhAgentId}</strong></div>
            <div className={styles.deviceInfoCard}><span>Package</span><strong>{packageName}</strong></div>
            <div className={styles.deviceInfoCard}><span>Version</span><strong>{packageVersion}</strong></div>
            <div className={styles.deviceInfoCard}><span>Vendor / type</span><strong>{vendorType}</strong></div>
          </div>"""

new_block = """          <div className={styles.keyValueList}>
            <KeyValueRow label="Hostname:" value={hostname} />
            <KeyValueRow label="Operating system:" value={operatingSystem} />
            <KeyValueRow label="Wazuh Agent:" value={wazuhAgentId} />
            <KeyValueRow label="Package:" value={packageName} />
            <KeyValueRow label="Version:" value={packageVersion} />
            <KeyValueRow label="Vendor / type:" value={vendorType} />
          </div>"""

if old_block not in text:
    raise SystemExit("Không tìm thấy block Thiết bị và package cũ để thay.")

text = text.replace(old_block, new_block, 1)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)

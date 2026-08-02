from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-wazuh-links-layout-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Lấy đúng Wazuh Agent từ device.wazuhBinding.
old_agent = """  const wazuhAgentId = getString(item, [['wazuhAgentId'], ['device', 'wazuhAgentId'], ['wazuhAgentBinding', 'wazuhAgentId']]) ?? '—';"""

new_agent = """  const wazuhAgentId =
    getString(item, [
      ['wazuhAgentId'],
      ['device', 'wazuhAgentId'],
      ['wazuhAgentBinding', 'wazuhAgentId'],
      ['device', 'wazuhBinding', 'wazuhAgentId'],
    ]) ?? null;

  const wazuhAgentName =
    getString(item, [
      ['wazuhAgentName'],
      ['device', 'wazuhAgentName'],
      ['wazuhAgentBinding', 'wazuhAgentName'],
      ['device', 'wazuhBinding', 'wazuhAgentName'],
    ]) ?? null;

  const wazuhAgentLabel =
    wazuhAgentName && wazuhAgentId
      ? `${wazuhAgentName} · ID ${wazuhAgentId}`
      : wazuhAgentName ?? wazuhAgentId ?? '—';"""

if old_agent not in text:
    raise SystemExit("Không tìm thấy dòng const wazuhAgentId cũ để thay.")

text = text.replace(old_agent, new_agent, 1)

text = text.replace(
    '<KeyValueRow label="Wazuh Agent:" value={wazuhAgentId} />',
    '<KeyValueRow label="Wazuh Agent:" value={wazuhAgentLabel} />',
)

text = text.replace(
    '<div className={styles.deviceInfoCard}><span>Wazuh Agent</span><strong>{wazuhAgentId}</strong></div>',
    '<div className={styles.deviceInfoCard}><span>Wazuh Agent</span><strong>{wazuhAgentLabel}</strong></div>',
)

# 2. Bỏ Feature hash trong Kết quả AI_CYRP.
text = text.replace(
    "  const featureHash = getString(item, [['featureVector', 'featureHash']]) ?? '—';\n",
    "",
)

text = text.replace(
    '            <KeyValueRow label="Feature hash" value={featureHash} />\n',
    "",
)

# 3. Tạo article Đường link khắc phục để đặt vào vị trí Endpoint context.
links_article = """        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Đường link khắc phục</h2>
              <p>Các liên kết mở ở tab mới để không đè lên trang CYRP hiện tại.</p>
            </div>
          </div>

          <div className={styles.cardList}>
            {links.map((link) => (
              <article className={styles.referenceCard} key={link.url}>
                <div>
                  <strong>{link.label}</strong>
                  <span>{link.note}</span>
                </div>
                <a className={styles.linkButton} href={link.url} target="_blank" rel="noreferrer">
                  Mở nguồn
                </a>
              </article>
            ))}
          </div>
        </article>
"""

endpoint_start = text.find("""        <article className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2>Endpoint context</h2>""")

if endpoint_start < 0:
    raise SystemExit("Không tìm thấy article Endpoint context để thay.")

endpoint_end = text.find("        </article>", endpoint_start)

if endpoint_end < 0:
    raise SystemExit("Không tìm thấy điểm kết thúc article Endpoint context.")

endpoint_end = endpoint_end + len("        </article>\n")

text = text[:endpoint_start] + links_article + text[endpoint_end:]

# 4. Xóa section Đường link khắc phục cũ ở phía dưới để không bị lặp.
old_links_start = text.find("""      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Đường link khắc phục</h2>""")

if old_links_start >= 0:
    history_start = text.find("""      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <div>
            <h2>Lịch sử dự đoán gần nhất</h2>""", old_links_start)

    if history_start < 0:
        raise SystemExit("Tìm thấy Đường link khắc phục cũ nhưng không tìm thấy section Lịch sử để cắt.")

    text = text[:old_links_start] + text[history_start:]

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)

from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-remediation-link-layout-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

old = """          {links.map((link) => (
            <article className={styles.referenceCard} key={link.url}>
              <div>
                <strong>{link.label}</strong>
                <span>{link.note}</span>
              </div>
              <a className={styles.linkButton} href={link.url} target="_blank" rel="noreferrer">
                Mở nguồn
              </a>
            </article>
          ))}"""

new = """          {links.map((link) => (
            <article
              className={styles.referenceCard}
              key={link.url}
              style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(0, 1fr) auto',
                alignItems: 'center',
                gap: '14px',
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  display: 'grid',
                  gap: '5px',
                  minWidth: 0,
                }}
              >
                <strong
                  style={{
                    display: 'block',
                    overflowWrap: 'anywhere',
                    lineHeight: 1.35,
                  }}
                >
                  {link.label}
                </strong>
                <span
                  style={{
                    display: 'block',
                    overflowWrap: 'anywhere',
                    wordBreak: 'break-word',
                    lineHeight: 1.5,
                  }}
                >
                  {link.note}
                </span>
              </div>

              <a
                className={styles.linkButton}
                href={link.url}
                target="_blank"
                rel="noreferrer"
                style={{
                  whiteSpace: 'nowrap',
                  justifySelf: 'end',
                }}
              >
                Mở nguồn
              </a>
            </article>
          ))}"""

if old not in text:
    raise SystemExit("Không tìm thấy block links.map cũ để thay. Cần kiểm tra lại file ai-prediction-detail-client.tsx.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)

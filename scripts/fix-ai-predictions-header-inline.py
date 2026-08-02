from pathlib import Path
from datetime import datetime
import shutil
import re

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
path = root / "apps" / "user-web" / "src" / "app" / "ai-predictions" / "ai-predictions-client.tsx"

backup = path.with_suffix(".tsx.bak-final-ai-header-inline-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

start = text.find("<header")
end = text.find("</header>", start)

if start == -1 or end == -1:
    raise SystemExit("Không tìm thấy header trong ai-predictions-client.tsx")

end = end + len("</header>")

new_header = '''<header
        className={styles.pageHeader}
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) auto',
          alignItems: 'start',
          columnGap: '24px',
          width: '100%',
        }}
      >
        <div style={{ minWidth: 0 }}>
          <p className={styles.eyebrow}>AI_CYRP prediction results</p>
          <h1>Kết quả AI dự đoán</h1>
          <p>
            Trang này hiển thị kết quả dự đoán của model AI_CYRP cho các CVE đang được Wazuh ghi nhận.
          </p>
        </div>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
            justifyContent: 'flex-start',
            gap: '10px',
            minWidth: '120px',
          }}
        >
          <button
            className={styles.secondaryButton}
            type="button"
            onClick={() => {
              setPage(1);
              void load();
            }}
            disabled={loading}
          >
            {loading ? 'Đang tải...' : 'Làm mới'}
          </button>

          <span className={`${styles.statusPill} ${styles.statusNeutral}`}>
            {data?.total ?? 0} bản ghi
          </span>
        </div>
      </header>'''

text = text[:start] + new_header + text[end:]

# Nếu còn button Làm mới dư sau header thì xóa nó.
header_end = text.find("</header>") + len("</header>")
before = text[:header_end]
after = text[header_end:]

matches = list(re.finditer(r"\n\s*<button[\s\S]*?\{loading \? 'Đang tải\.\.\.' : 'Làm mới'\}[\s\S]*?</button>", after))

if matches:
    m = matches[0]
    after = after[:m.start()] + after[m.end():]

text = before + after

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("Remaining Lam moi occurrences:", text.count("Làm mới"))

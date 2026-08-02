from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\ai-predictions-client.tsx")

if not path.exists():
    raise SystemExit(f"Không tìm thấy file: {path}")

backup = path.with_suffix(path.suffix + ".bak-fix-duplicate-percentile-functions-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

def find_matching_brace(source: str, open_index: int) -> int:
    depth = 0
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    i = open_index

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1

def remove_all_functions(source: str, name: str):
    removed = 0

    while True:
        start = source.find(f"function {name}(")

        if start < 0:
            break

        open_brace = source.find("{", start)
        if open_brace < 0:
            break

        close_brace = find_matching_brace(source, open_brace)
        if close_brace < 0:
            break

        end = close_brace + 1

        while end < len(source) and source[end] in "\r\n":
            end += 1

        source = source[:start] + source[end:]
        removed += 1

    return source, removed

for fn in ["percentileBandValue", "percentileBandClass", "percentileBandStyle", "percentileClass"]:
    text, count = remove_all_functions(text, fn)
    print(f"Removed {fn}: {count}")

helper = """function percentileBandValue(value: number | null): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1 ? value * 100 : value;
}

function percentileBandClass(value: number | null): string {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return styles.severityUnknown;
  }

  if (percent >= 85) {
    return styles.percentileCritical;
  }

  if (percent >= 65) {
    return styles.percentileHigh;
  }

  if (percent >= 45) {
    return styles.percentileMedium;
  }

  return styles.percentileLow;
}

function percentileBandStyle(value: number | null) {
  const percent = percentileBandValue(value);

  if (percent === null) {
    return {};
  }

  if (percent >= 85) {
    return {
      color: '#f87171',
      backgroundColor: 'rgba(239, 68, 68, 0.16)',
      borderColor: 'rgba(239, 68, 68, 0.42)',
    };
  }

  if (percent >= 65) {
    return {
      color: '#fb923c',
      backgroundColor: 'rgba(251, 146, 60, 0.16)',
      borderColor: 'rgba(251, 146, 60, 0.38)',
    };
  }

  if (percent >= 45) {
    return {
      color: '#facc15',
      backgroundColor: 'rgba(250, 204, 21, 0.14)',
      borderColor: 'rgba(250, 204, 21, 0.34)',
    };
  }

  return {
    color: '#34d399',
    backgroundColor: 'rgba(52, 211, 153, 0.14)',
    borderColor: 'rgba(52, 211, 153, 0.34)',
  };
}

"""

marker = "function statusClass("
if marker not in text:
    marker = "function severityClass("

if marker not in text:
    raise SystemExit("Không tìm thấy function statusClass hoặc severityClass để chèn helper.")

text = text.replace(marker, helper + marker, 1)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)
print("percentileBandValue count:", text.count("function percentileBandValue("))
print("percentileBandClass count:", text.count("function percentileBandClass("))
print("percentileBandStyle count:", text.count("function percentileBandStyle("))

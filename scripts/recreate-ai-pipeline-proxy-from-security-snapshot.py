from pathlib import Path
import re
import shutil
from datetime import datetime

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")
source = root / "apps" / "user-web" / "src" / "app" / "api" / "devices" / "[deviceId]" / "security-snapshot" / "route.ts"
target_dir = root / "apps" / "user-web" / "src" / "app" / "api" / "devices" / "[deviceId]" / "ai-pipeline-check"
target = target_dir / "route.ts"

if not source.exists():
    raise SystemExit(f"Không tìm thấy route nguồn đang hoạt động: {source}")

target_dir.mkdir(parents=True, exist_ok=True)

if target.exists():
    backup = target.with_suffix(".ts.bak-ai-pipeline-proxy-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(target, backup)
    print(f"Backup old target: {backup}")

text = source.read_text(encoding="utf-8")

# Keep all existing auth/proxy logic, only switch endpoint name and method.
text = text.replace("security-snapshot", "ai-pipeline-check")
text = text.replace("securitySnapshot", "aiPipelineCheck")
text = text.replace("SecuritySnapshot", "AiPipelineCheck")

text = re.sub(r"export\s+async\s+function\s+GET\s*\(", "export async function POST(", text)
text = re.sub(r"method:\s*'GET'", "method: 'POST'", text)
text = re.sub(r'method:\s*"GET"', 'method: "POST"', text)

target.write_text(text, encoding="utf-8")

print(f"Created proxy route: {target}")

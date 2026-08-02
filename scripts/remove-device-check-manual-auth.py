from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\components\device-analysis-button.tsx")
backup = path.with_suffix(".tsx.bak-remove-manual-auth-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# Remove the manually injected browserAuthorizationHeaders helper.
text = re.sub(
    r"\nfunction browserAuthorizationHeaders\(\): HeadersInit \{[\s\S]*?\n\}\n\ninterface DeviceAnalysisButtonProps",
    "\ninterface DeviceAnalysisButtonProps",
    text,
    count=1,
)

# Remove all manual Authorization header injection from fetch calls.
text = text.replace("          headers: browserAuthorizationHeaders(),\n", "")
text = text.replace("          headers: browserAuthorizationHeaders(),\r\n", "")

# Keep same-origin cookies.
text = re.sub(
    r"(`\/api\/devices\/\$\{deviceId\}\/ai-pipeline-check`,\s*\{\s*method: 'POST',\s*cache: 'no-store',)(\s*\})",
    r"\1\n          credentials: 'same-origin',\2",
    text,
    flags=re.S,
)

# Avoid duplicate credentials if previous patch already added it.
text = text.replace(
    "          credentials: 'same-origin',\n          credentials: 'same-origin',",
    "          credentials: 'same-origin',",
)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

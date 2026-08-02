from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\config\validation.schema.ts")

backup = path.with_suffix(".ts.bak-schema-clean-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1. Fix httpUrl block. Previous patch inserted env keys into Joi.UriOptions by mistake.
text = re.sub(
    r"const httpUrl = Joi\.string\(\)\.uri\(\{.*?\n\}\);",
    "const httpUrl = Joi.string().uri({\n  scheme: ['http', 'https'],\n});",
    text,
    flags=re.S,
)

# 2. Remove any existing AI/Wazuh pipeline schema entries if duplicated.
keys = [
    "AI_MODEL_ENABLED",
    "AI_MODEL_ACTIVE",
    "AI_MODEL_VERSION",
    "AI_MODEL_PYTHON_PATH",
    "AI_MODEL_PREDICT_SCRIPT",
    "AI_MODEL_RUNTIME_DIR",
    "AI_MODEL_TIMEOUT_MS",
    "AI_PIPELINE_MODEL_ROOT",
    "AI_PIPELINE_DATA_USER_DIR",
    "AI_PIPELINE_PYTHON_PATH",
    "AI_PIPELINE_TIMEOUT_MS",
    "WAZUH_INDEXER_USERNAME",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_INDEXER_REJECT_UNAUTHORIZED",
    "WAZUH_INDEXER_BASE_URL",
]

for key in keys:
    pattern = rf"(?ms)^\s*{re.escape(key)}\s*:\s*Joi\..*?(?=^\s*[A-Z][A-Z0-9_]*\s*:\s*Joi\.|\n\s*\}}\);|\Z)"
    text = re.sub(pattern, "", text)

# 3. Remove orphan Joi chains accidentally left at top-level before NODE_ENV.
# This targets the broken fragments that caused TS1003, without touching valid keyed schema entries.
text = re.sub(
    r"(?ms)^\s*\.(trim|min|valid|optional|required|default|uri|when)\(.*?(?=^\s*NODE_ENV\s*:\s*Joi\.)",
    "",
    text,
)

schema_insert = """  AI_MODEL_ENABLED: Joi.string().valid('true', 'false').optional(),
  AI_MODEL_ACTIVE: Joi.string().trim().optional(),
  AI_MODEL_VERSION: Joi.string().trim().optional(),
  AI_MODEL_PYTHON_PATH: Joi.string().trim().optional(),
  AI_MODEL_PREDICT_SCRIPT: Joi.string().trim().optional(),
  AI_MODEL_RUNTIME_DIR: Joi.string().trim().optional(),
  AI_MODEL_TIMEOUT_MS: Joi.number().integer().min(1000).optional(),

  AI_PIPELINE_MODEL_ROOT: Joi.string().trim().optional(),
  AI_PIPELINE_DATA_USER_DIR: Joi.string().trim().optional(),
  AI_PIPELINE_PYTHON_PATH: Joi.string().trim().optional(),
  AI_PIPELINE_TIMEOUT_MS: Joi.number().integer().min(1000).optional(),

  WAZUH_INDEXER_USERNAME: Joi.string().trim().optional(),
  WAZUH_INDEXER_PASSWORD: Joi.string().trim().optional(),
  WAZUH_INDEXER_REJECT_UNAUTHORIZED: Joi.string().valid('true', 'false').optional(),
  WAZUH_INDEXER_BASE_URL: httpUrl.optional(),

"""

# 4. Insert schema entries inside validationSchema object, right after Joi.object({
text = re.sub(
    r"export const validationSchema = Joi\.object\(\{\s*",
    "export const validationSchema = Joi.object({\n" + schema_insert,
    text,
    count=1,
)

# 5. Normalize missing indentation/comma around NODE_ENV if needed.
text = re.sub(r"\nNODE_ENV:", "\n  NODE_ENV:", text)

path.write_text(text, encoding="utf-8")

print(f"Fixed:  {path}")
print(f"Backup: {backup}")

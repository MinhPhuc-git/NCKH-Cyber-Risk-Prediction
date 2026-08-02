from pathlib import Path
import re
import shutil
import sys
from datetime import datetime

root = Path(sys.argv[1]).resolve()
patch_root = Path(sys.argv[2]).resolve()
backup_dir = root / '.phase-backups' / ('ai-pipeline-stable-v2-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
backup_dir.mkdir(parents=True, exist_ok=True)


def backup(path: Path) -> None:
    if path.exists():
        dest = backup_dir / path.relative_to(root).as_posix().replace('/', '__')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)


def copy_patch(rel: str) -> None:
    src = patch_root / rel
    dst = root / rel
    if not src.exists():
        raise SystemExit(f'Patch source not found: {src}')
    backup(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

# Copy backend service/controller and Next proxy route.
copy_patch('apps/api/src/modules/security-data/ai-pipeline-check.service.ts')
copy_patch('apps/api/src/modules/security-data/ai-pipeline-check.controller.ts')
copy_patch('apps/user-web/src/app/api/devices/[deviceId]/ai-pipeline-check/route.ts')

# Patch security-data.module.ts without overwriting unrelated module changes.
module_path = root / 'apps/api/src/modules/security-data/security-data.module.ts'
if not module_path.exists():
    raise SystemExit(f'Module not found: {module_path}')
backup(module_path)
text = module_path.read_text(encoding='utf-8')

if "./ai-pipeline-check.service" not in text:
    marker = "import { AiModelRuntimeService } from './ai-model-runtime.service';"
    if marker in text:
        text = text.replace(marker, marker + "\nimport { AiPipelineCheckService } from './ai-pipeline-check.service';")
    else:
        text = text.replace("import {", "import {", 1) + ""
        text = "import { AiPipelineCheckService } from './ai-pipeline-check.service';\n" + text

if "./ai-pipeline-check.controller" not in text:
    marker = "import { AdminSecurityDataController } from './admin-security-data.controller';"
    if marker in text:
        text = text.replace(marker, marker + "\nimport { AiPipelineCheckController } from './ai-pipeline-check.controller';")
    else:
        text = "import { AiPipelineCheckController } from './ai-pipeline-check.controller';\n" + text

# Add controller to controllers array.
text = re.sub(
    r"controllers:\s*\[([^\]]*)\]",
    lambda m: m.group(0) if 'AiPipelineCheckController' in m.group(1)
    else 'controllers: [' + m.group(1).rstrip() + (', ' if m.group(1).strip() else '') + 'AiPipelineCheckController]',
    text,
    count=1,
    flags=re.S,
)

# Add provider/export only if arrays exist.
for key in ['providers', 'exports']:
    text = re.sub(
        rf"{key}:\s*\[([^\]]*)\]",
        lambda m, key=key: m.group(0) if 'AiPipelineCheckService' in m.group(1)
        else f'{key}: [' + m.group(1).rstrip() + (', ' if m.group(1).strip() else '') + 'AiPipelineCheckService]',
        text,
        count=1,
        flags=re.S,
    )

module_path.write_text(text, encoding='utf-8')

# Remove older method added directly into SecurityDataController to avoid duplicate route registration.
controller_path = root / 'apps/api/src/modules/security-data/security-data.controller.ts'
if controller_path.exists():
    backup(controller_path)
    ctext = controller_path.read_text(encoding='utf-8')
    ctext = re.sub(r"^import \{ AiPipelineCheckService \} from './ai-pipeline-check\.service';\n", "", ctext, flags=re.M)
    ctext = re.sub(r"\n\s*private readonly aiPipelineCheck: AiPipelineCheckService,", "", ctext)
    ctext = re.sub(
        r"\n\s*@Post\('devices/:deviceId/ai-pipeline-check'\)[\s\S]*?\n\s*runAiPipelineCheck\([\s\S]*?\n\s*\}\n(?=\s*@|\s*\})",
        "\n",
        ctext,
        count=1,
    )
    controller_path.write_text(ctext, encoding='utf-8')

# Ensure validation schema includes AI_PIPELINE env keys but does not duplicate WAZUH_INDEXER_BASE_URL.
validation_path = root / 'apps/api/src/config/validation.schema.ts'
if validation_path.exists():
    backup(validation_path)
    vtext = validation_path.read_text(encoding='utf-8')
    # Remove duplicate top optional WAZUH_INDEXER_BASE_URL; keep original when(...) block if present.
    vtext = re.sub(r"(?m)^\s*WAZUH_INDEXER_BASE_URL:\s*httpUrl\.optional\(\),\r?\n", "", vtext)
    insert_lines = []
    needed = {
        "AI_MODEL_VERSION": "  AI_MODEL_VERSION: Joi.string().trim().optional(),",
        "AI_PIPELINE_MODEL_ROOT": "  AI_PIPELINE_MODEL_ROOT: Joi.string().trim().optional(),",
        "AI_PIPELINE_DATA_USER_DIR": "  AI_PIPELINE_DATA_USER_DIR: Joi.string().trim().optional(),",
        "AI_PIPELINE_PYTHON_PATH": "  AI_PIPELINE_PYTHON_PATH: Joi.string().trim().optional(),",
        "AI_PIPELINE_TIMEOUT_MS": "  AI_PIPELINE_TIMEOUT_MS: Joi.number().integer().min(30000).max(3600000).optional(),",
        "WAZUH_INDEXER_USERNAME": "  WAZUH_INDEXER_USERNAME: Joi.string().trim().optional(),",
        "WAZUH_INDEXER_PASSWORD": "  WAZUH_INDEXER_PASSWORD: Joi.string().trim().optional(),",
        "WAZUH_INDEXER_REJECT_UNAUTHORIZED": "  WAZUH_INDEXER_REJECT_UNAUTHORIZED: Joi.string().valid('true', 'false').optional(),",
    }
    for k, line in needed.items():
        if k not in vtext:
            insert_lines.append(line)
    if insert_lines:
        block = "\n".join(insert_lines) + "\n\n"
        vtext = re.sub(r"export const validationSchema = Joi\.object\(\{\s*", "export const validationSchema = Joi.object({\n" + block, vtext, count=1)
    validation_path.write_text(vtext, encoding='utf-8')

# Patch user-web button to call ai-pipeline-check and avoid clearing last successful data on failure.
component_path = root / 'apps/user-web/src/components/device-analysis-button.tsx'
if component_path.exists():
    backup(component_path)
    comp = component_path.read_text(encoding='utf-8')
    new_sync = r'''  async function syncNow(): Promise<void> {
    setIsModalOpen(true);

    if (isRunning) {
      setError('Kiểm tra AI đang chạy. Hệ thống sẽ giữ kết quả gần nhất trong lúc chờ phiên hiện tại hoàn tất.');
      return;
    }

    setIsRunning(true);
    setError('');
    setExpandedId(null);

    try {
      const response = await fetch(
        `/api/devices/${deviceId}/ai-pipeline-check`,
        {
          method: 'POST',
          cache: 'no-store',
        },
      );
      const payload = await response.json().catch(() => null) as
        | ApiErrorResponse
        | null;

      if (!response.ok) {
        throw new Error(
          errorMessage(
            payload as ApiErrorResponse,
            'Không thể chạy kiểm tra AI pipeline',
          ),
        );
      }

      await loadLatest().catch(() => undefined);
      await loadVulnerabilities();
    } catch (caught: unknown) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Không thể kiểm tra máy bằng AI pipeline',
      );

      await loadLatest().catch(() => undefined);
      await loadVulnerabilities().catch(() => undefined);
    } finally {
      setIsRunning(false);
    }
  }
'''
    comp2, n = re.subn(r"  async function syncNow\(\): Promise<void> \{[\s\S]*?\n  \}\n\n  function closeModal", new_sync + "\n  function closeModal", comp, count=1)
    if n == 1:
        comp = comp2
    else:
        print('WARN: syncNow() block not replaced in device-analysis-button.tsx')
    if "CYRP_XGBOOST_CVSS_PERCENTILE_V3" not in comp:
        comp = comp.replace(
            "  if (modelVersion === 'AI_CYRP_XGBOOST_V2') {\n    return 'AI_CYRP XGBoost';\n  }",
            "  if (modelVersion === 'CYRP_XGBOOST_CVSS_PERCENTILE_V3') {\n    return 'CYRP XGBoost CVSS Percentile';\n  }\n\n  if (modelVersion === 'AI_CYRP_XGBOOST_V2') {\n    return 'AI_CYRP XGBoost';\n  }",
        )
    component_path.write_text(comp, encoding='utf-8')

# Patch AI results page: risk level dropdown, remove Active dropdown.
user_src = root / 'apps/user-web/src'
candidates = []
if user_src.exists():
    for p in user_src.rglob('*.tsx'):
        try:
            t = p.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        if 'Mọi severity' in t and ('Kết quả AI' in t or 'AI_CYRP' in t or 'Kết quả chấm điểm' in t):
            candidates.append(p)

helpers = r'''
function normalizedAiRiskLevel(item: VulnerabilityItem): string {
  return (item.aiPrediction?.riskLevel ?? finalPriorityLevel(item) ?? '').toUpperCase();
}

function aiRiskLevelRank(level: string | null | undefined): number {
  switch (level?.toUpperCase()) {
    case 'CRITICAL': return 4;
    case 'HIGH': return 3;
    case 'MEDIUM': return 2;
    case 'LOW': return 1;
    default: return 0;
  }
}

function aiScoreForSort(item: VulnerabilityItem): number {
  const percentile = item.aiPrediction?.predictedPercentile;
  if (typeof percentile === 'number' && Number.isFinite(percentile)) {
    return percentile > 1 ? percentile / 100 : percentile;
  }

  const probability = item.aiPrediction?.attackProbability;
  if (typeof probability === 'number' && Number.isFinite(probability)) {
    return probability > 1 ? probability / 100 : probability;
  }

  return -1;
}

function sortAndFilterByAiRiskLevel(
  items: VulnerabilityItem[],
  riskLevel: string,
): VulnerabilityItem[] {
  const normalizedFilter = riskLevel.trim().toUpperCase();

  return [...items]
    .filter((item) => !normalizedFilter || normalizedAiRiskLevel(item) === normalizedFilter)
    .sort((left, right) => {
      const rankDelta =
        aiRiskLevelRank(normalizedAiRiskLevel(right)) -
        aiRiskLevelRank(normalizedAiRiskLevel(left));

      return rankDelta !== 0
        ? rankDelta
        : aiScoreForSort(right) - aiScoreForSort(left);
    });
}
'''

for page in candidates:
    backup(page)
    t = page.read_text(encoding='utf-8')
    t = t.replace("const [severity, setSeverity] = useState('');", "const [riskLevel, setRiskLevel] = useState('');")
    t = re.sub(r"\s*const \[status, setStatus\] = useState\('[^']*'\);\n", "\n", t)
    if 'function sortAndFilterByAiRiskLevel(' not in t:
        m = re.search(r"function statusClass\([^)]*\)\s*:\s*string\s*\{.*?\n\}\n", t, flags=re.S)
        if m:
            t = t[:m.end()] + "\n" + helpers + "\n" + t[m.end():]
        else:
            t = helpers + "\n" + t
    t = t.replace("if (severity) params.set('severity', severity);", "if (riskLevel) params.set('riskLevel', riskLevel);\n      params.set('status', 'ACTIVE');")
    t = re.sub(r"\s*if \(status\) params\.set\('status', status\);\n", "\n", t)
    if "sortAndFilterByAiRiskLevel(payload.items" not in t:
        t = t.replace(
            "      setData(payload);\n      setError('');",
            "      const filteredItems = sortAndFilterByAiRiskLevel(payload.items ?? [], riskLevel);\n      setData({\n        ...payload,\n        items: filteredItems,\n        total: riskLevel ? filteredItems.length : payload.total,\n      });\n      setError('');",
        )
    t = t.replace('}, [page, query, severity, status]);', '}, [page, query, riskLevel]);')
    t = t.replace('}, [page, query, severity]);', '}, [page, query, riskLevel]);')
    risk_select = '''        <select
          className={styles.select}
          value={riskLevel}
          onChange={(event) => {
            setRiskLevel(event.target.value);
            setPage(1);
          }}
          aria-label="Lọc theo risk level AI"
        >
          <option value="">Mọi risk level</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>'''
    t = re.sub(r"\s*<select\s+className=\{styles\.select\}\s+value=\{severity\}.*?<option value=\"\">Mọi severity</option>.*?</select>", "\n" + risk_select, t, count=1, flags=re.S)
    t = re.sub(r"\s*<select\s+className=\{styles\.select\}\s+value=\{status\}.*?</select>", "", t, count=1, flags=re.S)
    t = t.replace('Mọi severity', 'Mọi risk level')
    page.write_text(t, encoding='utf-8')

print('DONE')
print(f'Backup: {backup_dir}')

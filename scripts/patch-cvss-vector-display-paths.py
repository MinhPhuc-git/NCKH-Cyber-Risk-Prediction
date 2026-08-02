from pathlib import Path
from datetime import datetime
import shutil

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\user-web\src\app\ai-predictions\[id]\ai-prediction-detail-client.tsx")

backup = path.with_suffix(path.suffix + ".bak-cvss-vector-paths-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

insert_after = """  const description =
    getString(item, [['cve', 'description'], ['description']]) ??
    'Chưa có mô tả CVE.';

"""

vector_vars = """  const cvssVector = getString(item, [
    ['featureVector', 'vector'],
    ['featureVector', 'vectorString'],
    ['cve', 'cvssMetrics', '0', 'vectorString'],
    ['cve', 'cvssMetrics', '0', 'cvssVector'],
    ['rawPayload', 'vulnerability', 'cvss', 'vector'],
    ['rawPayload', 'cvss', 'vector'],
    ['raw_payload', 'vulnerability', 'cvss', 'vector'],
    ['raw_payload', 'cvss', 'vector'],
  ]) ?? '—';

  const cvssAttackVector = getString(item, [
    ['featureVector', 'attackVector'],
    ['cve', 'cvssMetrics', '0', 'attackVector'],
    ['rawPayload', 'vulnerability', 'cvss', 'attack_vector'],
    ['rawPayload', 'cvss', 'attack_vector'],
    ['raw_payload', 'vulnerability', 'cvss', 'attack_vector'],
    ['raw_payload', 'cvss', 'attack_vector'],
  ]) ?? '—';

  const cvssAttackComplexity = getString(item, [
    ['featureVector', 'attackComplexity'],
    ['cve', 'cvssMetrics', '0', 'attackComplexity'],
    ['rawPayload', 'vulnerability', 'cvss', 'attack_complexity'],
    ['rawPayload', 'cvss', 'attack_complexity'],
    ['raw_payload', 'vulnerability', 'cvss', 'attack_complexity'],
    ['raw_payload', 'cvss', 'attack_complexity'],
  ]) ?? '—';

  const cvssPrivilegesRequired = getString(item, [
    ['featureVector', 'privilegesRequired'],
    ['cve', 'cvssMetrics', '0', 'privilegesRequired'],
    ['rawPayload', 'vulnerability', 'cvss', 'privileges_required'],
    ['rawPayload', 'cvss', 'privileges_required'],
    ['raw_payload', 'vulnerability', 'cvss', 'privileges_required'],
    ['raw_payload', 'cvss', 'privileges_required'],
  ]) ?? '—';

  const cvssUserInteraction = getString(item, [
    ['featureVector', 'userInteraction'],
    ['cve', 'cvssMetrics', '0', 'userInteraction'],
    ['rawPayload', 'vulnerability', 'cvss', 'user_interaction'],
    ['rawPayload', 'cvss', 'user_interaction'],
    ['raw_payload', 'vulnerability', 'cvss', 'user_interaction'],
    ['raw_payload', 'cvss', 'user_interaction'],
  ]) ?? '—';

  const cvssCia =
    `${getString(item, [['featureVector', 'confidentialityImpact'], ['cve', 'cvssMetrics', '0', 'confidentialityImpact']]) ?? '—'} / ${getString(item, [['featureVector', 'integrityImpact'], ['cve', 'cvssMetrics', '0', 'integrityImpact']]) ?? '—'} / ${getString(item, [['featureVector', 'availabilityImpact'], ['cve', 'cvssMetrics', '0', 'availabilityImpact']]) ?? '—'}`;

"""

if insert_after not in text:
    raise SystemExit("Không tìm thấy vị trí chèn biến CVSS vector.")

if "const cvssVector =" not in text:
    text = text.replace(insert_after, insert_after + vector_vars, 1)

text = text.replace(
    '<KeyValueRow label="Vector" value={getString(item, [[\'featureVector\', \'vector\']]) ?? \'—\'} />',
    '<KeyValueRow label="Vector" value={cvssVector} />',
)

text = text.replace(
    '<KeyValueRow label="Attack vector" value={getString(item, [[\'featureVector\', \'attackVector\']]) ?? \'—\'} />',
    '<KeyValueRow label="Attack vector" value={cvssAttackVector} />',
)

text = text.replace(
    '<KeyValueRow label="Attack complexity" value={getString(item, [[\'featureVector\', \'attackComplexity\']]) ?? \'—\'} />',
    '<KeyValueRow label="Attack complexity" value={cvssAttackComplexity} />',
)

text = text.replace(
    '<KeyValueRow label="Privileges required" value={getString(item, [[\'featureVector\', \'privilegesRequired\']]) ?? \'—\'} />',
    '<KeyValueRow label="Privileges required" value={cvssPrivilegesRequired} />',
)

text = text.replace(
    '<KeyValueRow label="User interaction" value={getString(item, [[\'featureVector\', \'userInteraction\']]) ?? \'—\'} />',
    '<KeyValueRow label="User interaction" value={cvssUserInteraction} />',
)

old_cia = """            <KeyValueRow
              label="C / I / A"
              value={`${getString(item, [['featureVector', 'confidentialityImpact']]) ?? '—'} / ${getString(item, [['featureVector', 'integrityImpact']]) ?? '—'} / ${getString(item, [['featureVector', 'availabilityImpact']]) ?? '—'}`}
            />"""

new_cia = """            <KeyValueRow
              label="C / I / A"
              value={cvssCia}
            />"""

text = text.replace(old_cia, new_cia)

path.write_text(text, encoding="utf-8")

print("Patched:", path)
print("Backup:", backup)

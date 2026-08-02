from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\LuanVan\test\cyrp-platform-phase2")

importer = root / "apps/api/src/modules/security-data/ai-pipeline-data-user-import.service.ts"
sync = root / "apps/api/src/modules/security-data/security-data-sync.service.ts"

for path in [importer, sync]:
    if not path.exists():
        raise SystemExit(f"Không tìm thấy file: {path}")
    backup = path.with_suffix(path.suffix + ".bak-merge-ai-explanation-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    print("Backup:", backup)

# Patch Data User importer.
text = importer.read_text(encoding="utf-8")

old = """    const predictedAt = new Date();
    const explanation = this.buildExplanation(record, agentId, predictedAt);

    await this.database.aiPrediction.upsert({"""

new = """    const predictedAt = new Date();
    const explanation = this.buildExplanation(record, agentId, predictedAt);

    const existingPrediction = await this.database.aiPrediction.findUnique({
      where: { detectedVulnerabilityId: detection.id },
      select: { explanation: true },
    });

    const mergedExplanation = this.mergePredictionExplanation(
      explanation,
      existingPrediction?.explanation,
    );

    await this.database.aiPrediction.upsert({"""

if old in text and "const mergedExplanation = this.mergePredictionExplanation(" not in text:
    text = text.replace(old, new, 1)

text = text.replace(
    "explanation: explanation as Prisma.InputJsonValue",
    "explanation: mergedExplanation as Prisma.InputJsonValue",
)

helper_marker = "  private extractRecords("

helper = """  private mergePredictionExplanation(
    incoming: Record<string, unknown>,
    existingValue: unknown,
  ): Record<string, unknown> {
    const existing = this.isRecord(existingValue) ? existingValue : {};
    const merged: Record<string, unknown> = {
      ...existing,
      ...incoming,
    };

    const incomingReasons = Array.isArray(incoming.reasons) ? incoming.reasons : [];
    const existingReasons = Array.isArray(existing.reasons) ? existing.reasons : [];

    const incomingRawModelOutput = this.isRecord(incoming.rawModelOutput)
      ? incoming.rawModelOutput
      : null;
    const existingRawModelOutput = this.isRecord(existing.rawModelOutput)
      ? existing.rawModelOutput
      : null;

    const incomingRawReasons =
      incomingRawModelOutput && Array.isArray(incomingRawModelOutput.Reasons)
        ? incomingRawModelOutput.Reasons
        : [];

    if (incomingReasons.length > 0) {
      merged.reasons = incomingReasons;
    } else if (incomingRawReasons.length > 0) {
      merged.reasons = incomingRawReasons;
    } else if (existingReasons.length > 0) {
      merged.reasons = existingReasons;
    }

    if (!incomingRawModelOutput && existingRawModelOutput) {
      merged.rawModelOutput = existingRawModelOutput;
    }

    const incomingRemediation = this.isRecord(incoming.remediation)
      ? incoming.remediation
      : null;
    const existingRemediation = this.isRecord(existing.remediation)
      ? existing.remediation
      : null;

    if (!incomingRemediation && existingRemediation) {
      merged.remediation = existingRemediation;
    }

    return merged;
  }

"""

if "private mergePredictionExplanation(" not in text:
    if helper_marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn mergePredictionExplanation trong ai-pipeline-data-user-import.service.ts")
    text = text.replace(helper_marker, helper + helper_marker, 1)

importer.write_text(text, encoding="utf-8")
print("Patched importer:", importer)

# Patch Wazuh/security sync, tránh ghi đè mất Reasons.
text = sync.read_text(encoding="utf-8")

old = """      await this.database.aiPrediction.upsert({
        where: { detectedVulnerabilityId: detection.id },"""

new = """      const existingAiPrediction = await this.database.aiPrediction.findUnique({
        where: { detectedVulnerabilityId: detection.id },
        select: { explanation: true },
      });

      const mergedExplanation = this.mergePredictionExplanation(
        prediction.explanation,
        existingAiPrediction?.explanation,
      );

      await this.database.aiPrediction.upsert({
        where: { detectedVulnerabilityId: detection.id },"""

if old in text and "const existingAiPrediction = await this.database.aiPrediction.findUnique" not in text:
    text = text.replace(old, new, 1)

text = text.replace(
    "explanation: prediction.explanation as Prisma.InputJsonValue",
    "explanation: mergedExplanation as Prisma.InputJsonValue",
)

helper_marker = "  private finalPriority("

helper = """  private cyrpIsRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  private mergePredictionExplanation(
    incoming: Record<string, unknown>,
    existingValue: unknown,
  ): Record<string, unknown> {
    const existing = this.cyrpIsRecord(existingValue) ? existingValue : {};
    const merged: Record<string, unknown> = {
      ...existing,
      ...incoming,
    };

    const incomingReasons = Array.isArray(incoming.reasons) ? incoming.reasons : [];
    const existingReasons = Array.isArray(existing.reasons) ? existing.reasons : [];

    const incomingRawModelOutput = this.cyrpIsRecord(incoming.rawModelOutput)
      ? incoming.rawModelOutput
      : null;
    const existingRawModelOutput = this.cyrpIsRecord(existing.rawModelOutput)
      ? existing.rawModelOutput
      : null;

    const incomingRawReasons =
      incomingRawModelOutput && Array.isArray(incomingRawModelOutput.Reasons)
        ? incomingRawModelOutput.Reasons
        : [];

    if (incomingReasons.length > 0) {
      merged.reasons = incomingReasons;
    } else if (incomingRawReasons.length > 0) {
      merged.reasons = incomingRawReasons;
    } else if (existingReasons.length > 0) {
      merged.reasons = existingReasons;
    }

    if (!incomingRawModelOutput && existingRawModelOutput) {
      merged.rawModelOutput = existingRawModelOutput;
    }

    const incomingRemediation = this.cyrpIsRecord(incoming.remediation)
      ? incoming.remediation
      : null;
    const existingRemediation = this.cyrpIsRecord(existing.remediation)
      ? existing.remediation
      : null;

    if (!incomingRemediation && existingRemediation) {
      merged.remediation = existingRemediation;
    }

    return merged;
  }

"""

if "private cyrpIsRecord(" not in text:
    if helper_marker not in text:
        raise SystemExit("Không tìm thấy vị trí chèn mergePredictionExplanation trong security-data-sync.service.ts")
    text = text.replace(helper_marker, helper + helper_marker, 1)

sync.write_text(text, encoding="utf-8")
print("Patched sync:", sync)

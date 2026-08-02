from pathlib import Path
import shutil
from datetime import datetime

path = Path(r"D:\LuanVan\test\cyrp-platform-phase2\apps\api\src\modules\security-data\ai-pipeline-check.service.ts")

backup = path.with_suffix(".ts.bak-fix-delta-placement-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

# 1) Ensure interface has optional delta fields.
old_interface_part = """  importResult: DataUserImportResult;
  activeVulnerabilities: number;
  topPredictions: TopPredictionItem[];
}"""

new_interface_part = """  importResult: DataUserImportResult;
  activeVulnerabilities: number;
  topPredictions: TopPredictionItem[];
  skippedBecauseNoNewCve?: boolean;
  message?: string;
  delta?: unknown;
}"""

if old_interface_part in text and "skippedBecauseNoNewCve?: boolean;" not in text:
    text = text.replace(old_interface_part, new_interface_part)

# 2) Remove misplaced delta block that was inserted outside runForUserDevice().
start_marker = "const delta = await this.cveLifecycleDelta.prepareForAgent(wazuhAgentId);"
end_marker = "  private async runPipeline(): Promise<PipelineStepResult> {"

start = text.find(start_marker)
end = text.find(end_marker)

if start != -1 and end != -1 and start < end:
    # Remove from the line containing start_marker up to just before runPipeline().
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = start
    text = text[:line_start] + "\n" + text[end:]

# 3) Replace old full extract/run sequence inside runForUserDevice with delta-aware sequence.
old_sequence = """    steps.push(await this.runExtractFromWazuh(wazuhAgentId));
    steps.push(await this.ensureXgboostModel());
    steps.push(await this.runPipeline());

    const importResult = await this.importer.importForUserDevice(userId, deviceId);"""

new_sequence = """    const delta = await this.cveLifecycleDelta.prepareForAgent(wazuhAgentId);

    steps.push({
      step: 'cve-lifecycle-delta',
      command: 'Extract_Data_Wazuh.py --existing-pairs --new-only',
      skipped: false,
      durationMs: delta.command.durationMs,
      stdoutTail:
        delta.command.stdout.length > 3000
          ? delta.command.stdout.slice(-3000)
          : delta.command.stdout,
      stderrTail:
        delta.command.stderr.length > 3000
          ? delta.command.stderr.slice(-3000)
          : delta.command.stderr,
    });

    if (!delta.shouldRunPipeline) {
      const [activeVulnerabilities, topPredictions] = await Promise.all([
        this.database.detectedVulnerability.count({
          where: {
            deviceId,
            status: VulnerabilityLifecycleStatus.ACTIVE,
          },
        }),
        this.loadTopPredictions(deviceId),
      ]);

      const completedAt = new Date();

      return {
        deviceId,
        wazuhAgentId,
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        durationMs: completedAt.getTime() - startedAt.getTime(),
        steps,
        skippedBecauseNoNewCve: true,
        message:
          'Không có CVE mới hoặc CVE stale cần dự đoán lại. Hệ thống giữ kết quả AI hiện tại.',
        delta,
        importResult: {
          filesFound: 0,
          filesDeleted: 0,
          recordsRead: 0,
          recordsImported: 0,
          vulnerabilitiesCreated: 0,
          historyRowsCreated: 0,
          skipped: [],
          errors: [],
        },
        activeVulnerabilities,
        topPredictions,
      };
    }

    steps.push(await this.ensureXgboostModel());
    steps.push(await this.runPipeline());

    const importResult = await this.importer.importForUserDevice(userId, deviceId);"""

if old_sequence not in text:
    raise SystemExit("Không tìm thấy old_sequence trong runForUserDevice. Cần gửi lại đoạn lines 170-210 của file service.")
else:
    text = text.replace(old_sequence, new_sequence)

path.write_text(text, encoding="utf-8")

print(f"Patched: {path}")
print(f"Backup:  {backup}")

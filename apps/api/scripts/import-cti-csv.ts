import {
  CtiSourceStatus,
  PrismaClient,
  SyncRunStatus,
  SyncSourceType,
} from '@prisma/client';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { config } from 'dotenv';

function findRepositoryRoot(startDirectory: string): string {
  let candidate = resolve(startDirectory);

  while (true) {
    if (existsSync(resolve(candidate, 'pnpm-workspace.yaml'))) {
      return candidate;
    }

    const parent = dirname(candidate);
    if (parent === candidate) {
      throw new Error(
        'Không tìm thấy thư mục gốc CYRP (pnpm-workspace.yaml)',
      );
    }
    candidate = parent;
  }
}

const repositoryRoot = findRepositoryRoot(process.cwd());

config({ path: resolve(repositoryRoot, '.env') });

const prisma = new PrismaClient();

type CsvRow = Record<string, string>;

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];

    if (quoted) {
      if (character === '"') {
        if (input[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += character;
      }
      continue;
    }

    if (character === '"') {
      quoted = true;
    } else if (character === ',') {
      row.push(field);
      field = '';
    } else if (character === '\n') {
      row.push(field.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += character;
    }
  }

  if (quoted) {
    throw new Error('CSV contains an unterminated quoted field');
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field.replace(/\r$/, ''));
    rows.push(row);
  }

  return rows.filter((item) => item.some((value) => value.trim()));
}

function rowsFromCsv(input: string): CsvRow[] {
  const rows = parseCsv(input);
  const header = rows.shift()?.map((value) => value.trim());

  if (!header?.length) {
    throw new Error('CSV header is missing');
  }

  return rows.map((values, rowIndex) => {
    if (values.length > header.length) {
      throw new Error(`CSV row ${rowIndex + 2} has too many columns`);
    }

    return Object.fromEntries(
      header.map((name, columnIndex) => [name, values[columnIndex]?.trim() ?? '']),
    );
  });
}

function text(row: CsvRow, ...names: string[]): string | null {
  for (const name of names) {
    const value = row[name]?.trim();
    if (value) {
      return value;
    }
  }
  return null;
}

function numberValue(row: CsvRow, ...names: string[]): number | null {
  const value = text(row, ...names);
  if (!value) {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizedCveId(row: CsvRow): string | null {
  const value = text(row, 'cveId', 'cve_id', 'CVE_ID')?.toUpperCase() ?? null;
  return value && /^CVE-\d{4}-\d{4,}$/.test(value) ? value : null;
}

function normalizedCweId(row: CsvRow): string | null {
  const value = text(row, 'cweId', 'cwe_id', 'CWE_ID')?.toUpperCase() ?? null;
  return value && /^CWE-\d+$/.test(value) ? value : null;
}

function resolveInputFile(value: string): string {
  if (isAbsolute(value)) {
    return value;
  }

  const candidates = [
    resolve(process.cwd(), value),
    resolve(repositoryRoot, value),
  ];
  const existing = candidates.find((candidate) => existsSync(candidate));

  return existing ?? candidates[1];
}

async function main(): Promise<void> {
  const configuredPath = argument('file') ?? process.env.CTI_CSV_PATH;

  if (!configuredPath) {
    throw new Error('Provide --file <path> or set CTI_CSV_PATH');
  }

  const filePath = resolveInputFile(configuredPath);

  const content = await readFile(filePath, 'utf8');
  const sourceHash = sha256(content);
  const rows = rowsFromCsv(content);
  const source = await prisma.ctiSource.upsert({
    where: { code: 'CYRP_CTI_CSV' },
    create: {
      code: 'CYRP_CTI_CSV',
      name: 'CYRP normalized CTI CSV',
      sourceType: SyncSourceType.CTI_CSV,
      description: 'Nguồn CVE/CVSS/CWE chuẩn hóa cục bộ.',
      status: CtiSourceStatus.READY,
    },
    update: { enabled: true },
  });

  const run = await prisma.syncRun.create({
    data: {
      sourceId: source.id,
      sourceType: SyncSourceType.CTI_CSV,
      status: SyncRunStatus.RUNNING,
      trigger: 'CLI_IMPORT',
      sourceVersion: sourceHash,
      sourceManifest: {
        fileName: filePath.split(/[\\/]/).pop(),
        sha256: sourceHash,
      },
    },
  });

  let written = 0;
  let updated = 0;
  let rejected = 0;

  try {
    for (const row of rows) {
      const cveId = normalizedCveId(row);
      if (!cveId) {
        rejected += 1;
        continue;
      }

      const cweId = normalizedCweId(row);
      const cweDescription = text(row, 'cweDescription', 'description');
      const cvssVersion = text(row, 'version', 'cvssVersion') ?? 'UNKNOWN';
      const existed = await prisma.cve.findUnique({
        where: { cveId },
        select: { cveId: true },
      });

      await prisma.$transaction(async (transaction) => {
        await transaction.cve.upsert({
          where: { cveId },
          create: {
            cveId,
            description: text(row, 'cveDescription'),
            source: 'CYRP_CTI_CSV',
            sourceVersion: sourceHash,
            sourceDocumentHash: sha256(JSON.stringify(row)),
          },
          update: {
            ...(text(row, 'cveDescription')
              ? { description: text(row, 'cveDescription') }
              : {}),
            source: 'CYRP_CTI_CSV',
            sourceVersion: sourceHash,
            sourceDocumentHash: sha256(JSON.stringify(row)),
            ingestedAt: new Date(),
          },
        });

        await transaction.cveCvssMetric.upsert({
          where: {
            cveId_source_metricType_cvssVersion: {
              cveId,
              source: 'CYRP_CTI_CSV',
              metricType: 'PRIMARY',
              cvssVersion,
            },
          },
          create: {
            cveId,
            source: 'CYRP_CTI_CSV',
            metricType: 'PRIMARY',
            cvssVersion,
            vectorString: text(row, 'vectorString'),
            baseScore: numberValue(row, 'baseScore'),
            baseSeverity: text(row, 'baseSeverity')?.toUpperCase() ?? null,
            attackVector: text(row, 'attackVector'),
            attackComplexity: text(row, 'attackComplexity'),
            privilegesRequired: text(row, 'privilegesRequired'),
            userInteraction: text(row, 'userInteraction'),
            scope: text(row, 'scope'),
            confidentialityImpact: text(row, 'confidentialityImpact'),
            integrityImpact: text(row, 'integrityImpact'),
            availabilityImpact: text(row, 'availabilityImpact'),
          },
          update: {
            vectorString: text(row, 'vectorString'),
            baseScore: numberValue(row, 'baseScore'),
            baseSeverity: text(row, 'baseSeverity')?.toUpperCase() ?? null,
            attackVector: text(row, 'attackVector'),
            attackComplexity: text(row, 'attackComplexity'),
            privilegesRequired: text(row, 'privilegesRequired'),
            userInteraction: text(row, 'userInteraction'),
            scope: text(row, 'scope'),
            confidentialityImpact: text(row, 'confidentialityImpact'),
            integrityImpact: text(row, 'integrityImpact'),
            availabilityImpact: text(row, 'availabilityImpact'),
            ingestedAt: new Date(),
          },
        });

        if (cweId) {
          await transaction.cwe.upsert({
            where: { cweId },
            create: {
              cweId,
              description: cweDescription,
              source: 'CYRP_CTI_CSV',
            },
            update: {
              ...(cweDescription ? { description: cweDescription } : {}),
              source: 'CYRP_CTI_CSV',
            },
          });

          await transaction.cveCwe.upsert({
            where: {
              cveId_cweId_source: {
                cveId,
                cweId,
                source: 'CYRP_CTI_CSV',
              },
            },
            create: { cveId, cweId, source: 'CYRP_CTI_CSV' },
            update: {},
          });
        }
      });

      if (existed) {
        updated += 1;
      } else {
        written += 1;
      }
    }

    const status = rejected > 0 ? SyncRunStatus.PARTIAL : SyncRunStatus.COMPLETED;
    await prisma.$transaction([
      prisma.syncRun.update({
        where: { id: run.id },
        data: {
          status,
          completedAt: new Date(),
          recordsRead: rows.length,
          recordsWritten: written,
          recordsUpdated: updated,
          recordsRejected: rejected,
          checkpointAfter: { importedRows: written + updated },
          errorSummary: rejected > 0 ? `${rejected} dòng không có CVE ID hợp lệ` : null,
        },
      }),
      prisma.ctiSource.update({
        where: { id: source.id },
        data: {
          status: CtiSourceStatus.ACTIVE,
          lastAttemptAt: new Date(),
          lastSuccessAt: new Date(),
          lastError: null,
        },
      }),
    ]);

    console.log(
      JSON.stringify(
        { filePath, rows: rows.length, written, updated, rejected, status },
        null,
        2,
      ),
    );
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    await prisma.$transaction([
      prisma.syncRun.update({
        where: { id: run.id },
        data: {
          status: SyncRunStatus.FAILED,
          completedAt: new Date(),
          recordsRead: rows.length,
          recordsWritten: written,
          recordsUpdated: updated,
          recordsRejected: rejected,
          errorSummary: message.slice(0, 2000),
        },
      }),
      prisma.ctiSource.update({
        where: { id: source.id },
        data: {
          status: CtiSourceStatus.ERROR,
          lastAttemptAt: new Date(),
          lastError: message.slice(0, 2000),
        },
      }),
    ]);
    throw error;
  }
}

main()
  .catch((error: unknown) => {
    console.error('CTI CSV import failed');
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

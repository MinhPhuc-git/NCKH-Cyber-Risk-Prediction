import {
  CtiSourceStatus,
  PrismaClient,
  SyncSourceType,
} from '@prisma/client';
import { config } from 'dotenv';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

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

const sources = [
  {
    code: 'WAZUH_VULNERABILITY_STATE',
    name: 'Wazuh vulnerability state',
    sourceType: SyncSourceType.WAZUH_VULNERABILITIES,
    description:
      'Trạng thái lỗ hổng đã phát hiện trên từng Wazuh Agent.',
    enabled: true,
  },
  {
    code: 'WAZUH_ENDPOINT_CONTEXT',
    name: 'Wazuh endpoint context',
    sourceType: SyncSourceType.WAZUH_ENDPOINT_CONTEXT,
    description:
      'Inventory package, hotfix, port, process, service, system và hardware của endpoint.',
    enabled: true,
  },
  {
    code: 'CYRP_CTI_CSV',
    name: 'CYRP normalized CTI CSV',
    sourceType: SyncSourceType.CTI_CSV,
    description:
      'Nguồn CVE/CVSS/CWE chuẩn hóa cục bộ phục vụ làm giàu dữ liệu.',
    enabled: true,
  },
  {
    code: 'NVD_API',
    name: 'NVD CVE API',
    sourceType: SyncSourceType.CTI_NVD,
    description:
      'Nguồn mở rộng CVE, references và affected-product/CPE; adapter chưa bật trong Phase 2.',
    enabled: false,
  },
  {
    code: 'FIRST_EPSS',
    name: 'FIRST EPSS',
    sourceType: SyncSourceType.CTI_EPSS,
    description:
      'Snapshot EPSS theo ngày; adapter chưa bật trong Phase 2.',
    enabled: false,
  },
  {
    code: 'CISA_KEV',
    name: 'CISA Known Exploited Vulnerabilities',
    sourceType: SyncSourceType.CTI_CISA_KEV,
    description:
      'Known-exploited signal theo thời gian; adapter chưa bật trong Phase 2.',
    enabled: false,
  },
];

async function main(): Promise<void> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Phase 2 development seed must not run in production');
  }

  for (const source of sources) {
    await prisma.ctiSource.upsert({
      where: { code: source.code },
      create: {
        ...source,
        status: CtiSourceStatus.READY,
      },
      update: {
        name: source.name,
        sourceType: source.sourceType,
        description: source.description,
        enabled: source.enabled,
      },
    });
  }

  console.log(`Phase 2 source registry seeded: ${sources.length} sources`);
}

main()
  .catch((error: unknown) => {
    console.error('Phase 2 source seed failed');
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

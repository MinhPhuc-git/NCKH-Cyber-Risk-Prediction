import {
  CtiSourceStatus,
  PrismaClient,
  RoleCode,
  SyncSourceType,
  UserStatus,
} from '@prisma/client';
import { hash } from 'bcryptjs';
import { config } from 'dotenv';
import { resolve } from 'node:path';

config({
  path: resolve(process.cwd(), '../../.env'),
});

const prisma = new PrismaClient();

function getRequiredEnvironmentVariable(name: string): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}`,
    );
  }

  return value;
}

async function seedRoles(): Promise<void> {
  await prisma.role.upsert({
    where: {
      code: RoleCode.ADMIN,
    },
    update: {
      name: 'Administrator',
      description: 'Full administrative access to CYRP Platform',
    },
    create: {
      code: RoleCode.ADMIN,
      name: 'Administrator',
      description: 'Full administrative access to CYRP Platform',
    },
  });

  await prisma.role.upsert({
    where: {
      code: RoleCode.USER,
    },
    update: {
      name: 'User',
      description: 'Standard CYRP Platform user',
    },
    create: {
      code: RoleCode.USER,
      name: 'User',
      description: 'Standard CYRP Platform user',
    },
  });
}

async function seedAdministrator(): Promise<void> {
  const email = getRequiredEnvironmentVariable(
    'SEED_ADMIN_EMAIL',
  ).toLowerCase();

  const password = getRequiredEnvironmentVariable(
    'SEED_ADMIN_PASSWORD',
  );

  const fullName =
    process.env.SEED_ADMIN_NAME?.trim() ||
    'System Administrator';

  if (password.length < 12) {
    throw new Error(
      'SEED_ADMIN_PASSWORD must contain at least 12 characters',
    );
  }

  const adminRole = await prisma.role.findUniqueOrThrow({
    where: {
      code: RoleCode.ADMIN,
    },
  });

  const existingAdministrator = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (existingAdministrator) {
    await prisma.user.update({
      where: {
        id: existingAdministrator.id,
      },
      data: {
        fullName,
        status: UserStatus.ACTIVE,
        roleId: adminRole.id,
      },
    });

    console.log(`Administrator already exists: ${email}`);
    return;
  }

  const passwordHash = await hash(password, 12);

  await prisma.user.create({
    data: {
      email,
      fullName,
      passwordHash,
      status: UserStatus.ACTIVE,
      roleId: adminRole.id,
    },
  });

  console.log(`Administrator created: ${email}`);
}


async function seedDataSources(): Promise<void> {
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

  for (const source of sources) {
    await prisma.ctiSource.upsert({
      where: { code: source.code },
      create: {
        ...source,
        status: CtiSourceStatus.READY,
        enabled: source.enabled,
      },
      update: {
        name: source.name,
        sourceType: source.sourceType,
        description: source.description,
        enabled: source.enabled,
      },
    });
  }
}

async function main(): Promise<void> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'Development seed must not run in production',
    );
  }

  await seedRoles();
  await seedDataSources();
  await seedAdministrator();

  console.log('CYRP identity and data-source seed completed');
}

main()
  .catch((error: unknown) => {
    console.error('CYRP identity seed failed');

    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error(error);
    }

    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
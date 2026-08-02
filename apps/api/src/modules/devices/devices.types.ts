import type { Prisma } from '@prisma/client';

export const deviceResponseSelect = {
  id: true,
  hostname: true,
  operatingSystem: true,
  architecture: true,
  agentVersion: true,
  status: true,
  lastSeenAt: true,
  createdAt: true,
} satisfies Prisma.DeviceSelect;

export type DeviceResponseRecord =
  Prisma.DeviceGetPayload<{
    select: typeof deviceResponseSelect;
  }>;

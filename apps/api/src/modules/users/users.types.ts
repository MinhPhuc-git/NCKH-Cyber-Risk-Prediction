import type { Prisma } from '@prisma/client';

export type UserWithRole =
  Prisma.UserGetPayload<{
    include: {
      role: true;
    };
  }>;

export const userListSelect = {
  id: true,
  email: true,
  fullName: true,
  status: true,
  lastLoginAt: true,
  createdAt: true,
  role: {
    select: {
      code: true,
    },
  },
  devices: {
    select: {
      id: true,
      status: true,
      wazuhBinding: {
        select: {
          lastKnownStatus: true,
        },
      },
    },
  },
} satisfies Prisma.UserSelect;

export type UserListRecord =
  Prisma.UserGetPayload<{
    select: typeof userListSelect;
  }>;

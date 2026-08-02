import type { RoleCode } from '@prisma/client';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  role: RoleCode;
  iat?: number;
  exp?: number;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string;
  role: RoleCode;
}

export interface AuthenticatedRequest {
  headers: {
    authorization?: string;
    [key: string]: string | string[] | undefined;
  };

  user?: AuthenticatedUser;
}
import {
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import type {
  ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RoleCode } from '@prisma/client';

import type {
  AuthenticatedRequest,
} from '../auth.types';
import { RolesGuard } from './roles.guard';

describe('RolesGuard', () => {
  const reflectorMock = {
    getAllAndOverride: jest.fn(),
  };

  const guard = new RolesGuard(
    reflectorMock as unknown as Reflector,
  );

  function createContext(
    request: AuthenticatedRequest,
  ): ExecutionContext {
    return {
      switchToHttp: () => ({
        getRequest: () => request,
      }),
      getHandler: jest.fn(),
      getClass: jest.fn(),
    } as unknown as ExecutionContext;
  }

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('allows public routes', () => {
    reflectorMock.getAllAndOverride
      .mockReturnValueOnce(true);

    const result = guard.canActivate(
      createContext({
        headers: {},
      }),
    );

    expect(result).toBe(true);
  });

  it('allows authenticated routes without role metadata', () => {
    reflectorMock.getAllAndOverride
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(undefined);

    const result = guard.canActivate(
      createContext({
        headers: {},
        user: {
          id: 'user-id',
          email: 'user@cyrp.local',
          fullName: 'Test User',
          role: RoleCode.USER,
        },
      }),
    );

    expect(result).toBe(true);
  });

  it('allows a user with the required role', () => {
    reflectorMock.getAllAndOverride
      .mockReturnValueOnce(false)
      .mockReturnValueOnce([
        RoleCode.ADMIN,
      ]);

    const result = guard.canActivate(
      createContext({
        headers: {},
        user: {
          id: 'admin-id',
          email: 'admin@cyrp.local',
          fullName:
            'System Administrator',
          role: RoleCode.ADMIN,
        },
      }),
    );

    expect(result).toBe(true);
  });

  it('rejects a user without the required role', () => {
    reflectorMock.getAllAndOverride
      .mockReturnValueOnce(false)
      .mockReturnValueOnce([
        RoleCode.ADMIN,
      ]);

    expect(() =>
      guard.canActivate(
        createContext({
          headers: {},
          user: {
            id: 'user-id',
            email:
              'user@cyrp.local',
            fullName: 'Test User',
            role: RoleCode.USER,
          },
        }),
      ),
    ).toThrow(ForbiddenException);
  });

  it('rejects a missing authentication context', () => {
    reflectorMock.getAllAndOverride
      .mockReturnValueOnce(false)
      .mockReturnValueOnce([
        RoleCode.ADMIN,
      ]);

    expect(() =>
      guard.canActivate(
        createContext({
          headers: {},
        }),
      ),
    ).toThrow(UnauthorizedException);
  });
});
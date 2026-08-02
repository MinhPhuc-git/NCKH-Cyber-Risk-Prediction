import {
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';
import { hashSync } from 'bcryptjs';

import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  const password = 'AdminPassword123!';
  const passwordHash = hashSync(password, 4);

  const usersServiceMock = {
    findForAuthentication: jest.fn(),
    markAuthenticated: jest.fn(),
  };

  const jwtServiceMock = {
    signAsync: jest.fn(),
  };

  const service = new AuthService(
    usersServiceMock as unknown as UsersService,
    jwtServiceMock as unknown as JwtService,
  );

  const activeUser = {
    id: '2df130c6-7c35-4462-bc6d-4487b453eeb0',
    email: 'admin@cyrp.local',
    fullName: 'System Administrator',
    passwordHash,
    status: UserStatus.ACTIVE,
    roleId: '7b358110-9261-41f8-b7da-36aac2a30826',
    lastLoginAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    role: {
      id: '7b358110-9261-41f8-b7da-36aac2a30826',
      code: RoleCode.ADMIN,
      name: 'Administrator',
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();

    usersServiceMock.findForAuthentication
      .mockResolvedValue(activeUser);

    usersServiceMock.markAuthenticated
      .mockResolvedValue(undefined);

    jwtServiceMock.signAsync
      .mockResolvedValue('test-access-token');
  });

  it('returns an access token for valid credentials', async () => {
    const result = await service.login({
      email: activeUser.email,
      password,
    });

    expect(result).toEqual({
      accessToken: 'test-access-token',
      tokenType: 'Bearer',
      user: {
        id: activeUser.id,
        email: activeUser.email,
        fullName: activeUser.fullName,
        role: RoleCode.ADMIN,
      },
    });

    expect(
      usersServiceMock.markAuthenticated,
    ).toHaveBeenCalledWith(activeUser.id);
  });

  it('rejects an invalid password', async () => {
    await expect(
      service.login({
        email: activeUser.email,
        password: 'WrongPassword123!',
      }),
    ).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects a disabled account', async () => {
    usersServiceMock.findForAuthentication
      .mockResolvedValue({
        ...activeUser,
        status: UserStatus.DISABLED,
      });

    await expect(
      service.login({
        email: activeUser.email,
        password,
      }),
    ).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });
});
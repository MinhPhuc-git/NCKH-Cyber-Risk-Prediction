import { ApiProperty } from '@nestjs/swagger';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';

class UserListItemDto {
  @ApiProperty({
    format: 'uuid',
  })
  id!: string;

  @ApiProperty({
    format: 'email',
  })
  email!: string;

  @ApiProperty()
  fullName!: string;

  @ApiProperty({
    enum: RoleCode,
  })
  role!: RoleCode;

  @ApiProperty({
    enum: UserStatus,
  })
  status!: UserStatus;

  @ApiProperty({
    nullable: true,
  })
  lastLoginAt!: Date | null;

  @ApiProperty()
  createdAt!: Date;

  @ApiProperty()
  deviceCount!: number;

  @ApiProperty()
  activeDeviceCount!: number;

  @ApiProperty()
  hasActiveDevice!: boolean;
}

class PaginationDto {
  @ApiProperty()
  page!: number;

  @ApiProperty()
  limit!: number;

  @ApiProperty()
  total!: number;

  @ApiProperty()
  totalPages!: number;
}

class UserSummaryDto {
  @ApiProperty()
  total!: number;

  @ApiProperty()
  activeAccounts!: number;

  @ApiProperty()
  disabledAccounts!: number;

  @ApiProperty()
  usersWithActiveDevices!: number;

  @ApiProperty()
  usersWithoutActiveDevices!: number;
}

export class ListUsersResponseDto {
  @ApiProperty({
    type: [
      UserListItemDto,
    ],
  })
  data!: UserListItemDto[];

  @ApiProperty({
    type: PaginationDto,
  })
  pagination!: PaginationDto;

  @ApiProperty({
    type: UserSummaryDto,
  })
  summary!: UserSummaryDto;
}

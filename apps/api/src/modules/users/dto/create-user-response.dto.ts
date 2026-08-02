import { ApiProperty } from '@nestjs/swagger';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';

export class CreateUserResponseDto {
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
    example: RoleCode.USER,
  })
  role!: RoleCode;

  @ApiProperty({
    enum: UserStatus,
    example: UserStatus.ACTIVE,
  })
  status!: UserStatus;

  @ApiProperty()
  createdAt!: Date;
}

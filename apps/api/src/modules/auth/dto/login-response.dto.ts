import { ApiProperty } from '@nestjs/swagger';
import { RoleCode } from '@prisma/client';

export class AuthenticatedUserDto {
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
}

export class LoginResponseDto {
  @ApiProperty({
    description: 'JWT access token',
  })
  accessToken!: string;

  @ApiProperty({
    example: 'Bearer',
  })
  tokenType!: 'Bearer';

  @ApiProperty({
    type: AuthenticatedUserDto,
  })
  user!: AuthenticatedUserDto;
}
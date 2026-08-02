import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  RoleCode,
  UserStatus,
} from '@prisma/client';
import {
  Transform,
  Type,
} from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export class ListUsersQueryDto {
  @ApiPropertyOptional({
    default: 1,
    minimum: 1,
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  page = 1;

  @ApiPropertyOptional({
    default: 20,
    minimum: 1,
    maximum: 100,
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  @IsOptional()
  limit = 20;

  @ApiPropertyOptional({
    description:
      'Tìm kiếm theo email hoặc họ tên',
    maxLength: 254,
  })
  @Transform(
    ({ value }: { value: unknown }) => {
      if (typeof value !== 'string') {
        return value;
      }

      return value.trim();
    },
  )
  @IsString()
  @MaxLength(254)
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({
    enum: RoleCode,
  })
  @IsEnum(RoleCode)
  @IsOptional()
  role?: RoleCode;

  @ApiPropertyOptional({
    enum: UserStatus,
  })
  @IsEnum(UserStatus)
  @IsOptional()
  status?: UserStatus;
}
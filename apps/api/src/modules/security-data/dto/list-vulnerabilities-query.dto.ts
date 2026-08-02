import { Transform, Type } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { VulnerabilityLifecycleStatus } from '@prisma/client';

function emptyToUndefined(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === ''
    ? undefined
    : value;
}

export class ListVulnerabilitiesQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit = 25;

  @IsOptional()
  @Transform(({ value }) => emptyToUndefined(value))
  @IsUUID()
  deviceId?: string;

  @IsOptional()
  @Transform(({ value }) => emptyToUndefined(value))
  @IsUUID()
  ownerId?: string;

  @IsOptional()
  @Transform(({ value }) => emptyToUndefined(value))
  @IsEnum(VulnerabilityLifecycleStatus)
  status?: VulnerabilityLifecycleStatus;

  @IsOptional()
  @Transform(({ value }) => {
    const normalized = emptyToUndefined(value);
    return typeof normalized === 'string'
      ? normalized.trim().toUpperCase()
      : normalized;
  })
  @IsString()
  @MaxLength(30)
  severity?: string;

  @IsOptional()
  @Transform(({ value }) => emptyToUndefined(value))
  @IsString()
  @MaxLength(160)
  query?: string;
}

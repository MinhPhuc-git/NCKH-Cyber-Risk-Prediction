import { Transform, Type } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsOptional,
  IsUUID,
  Max,
  Min,
} from 'class-validator';
import {
  SyncRunStatus,
  SyncSourceType,
} from '@prisma/client';

function emptyToUndefined(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === ''
    ? undefined
    : value;
}

export class ListSyncRunsQueryDto {
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
  @Transform(({ value }) => {
    const normalized = emptyToUndefined(value);
    return typeof normalized === 'string'
      ? normalized.trim().toUpperCase()
      : normalized;
  })
  @IsEnum(SyncRunStatus)
  status?: SyncRunStatus;

  @IsOptional()
  @Transform(({ value }) => {
    const normalized = emptyToUndefined(value);
    return typeof normalized === 'string'
      ? normalized.trim().toUpperCase()
      : normalized;
  })
  @IsEnum(SyncSourceType)
  sourceType?: SyncSourceType;
}

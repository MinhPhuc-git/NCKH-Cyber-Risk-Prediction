import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsInt,
  IsOptional,
  Max,
  Min,
} from 'class-validator';

export class CreateAnalysisRunDto {
  @ApiPropertyOptional({
    default: 15,
    minimum: 1,
    maximum: 10080,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10080)
  windowMinutes = 15;
}

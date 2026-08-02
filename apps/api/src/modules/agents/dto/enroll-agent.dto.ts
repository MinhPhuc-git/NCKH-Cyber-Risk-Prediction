import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class EnrollAgentDto {
  @ApiProperty({
    example: 'CYRP-A7K9-M2Q4',
  })
  @Transform(({ value }: { value: unknown }) => {
    if (typeof value !== 'string') {
      return value;
    }

    return value.trim().toUpperCase();
  })
  @Matches(
    /^CYRP-[A-Z2-9]{4}-[A-Z2-9]{4}$/,
  )
  enrollmentCode!: string;

  @ApiProperty({
    format: 'uuid',
  })
  @IsUUID()
  installationId!: string;

  @ApiProperty({
    example: 'DESKTOP-ABC123',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  hostname!: string;

  @ApiProperty({
    example: 'Windows 11 Pro 24H2',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  operatingSystem!: string;

  @ApiProperty({
    required: false,
    example: 'AMD64',
  })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  architecture?: string;

  @ApiProperty({
    example: '0.1.0',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(30)
  agentVersion!: string;
}

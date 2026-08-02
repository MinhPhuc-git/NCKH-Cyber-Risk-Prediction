import {
  ApiProperty,
  ApiPropertyOptional,
} from '@nestjs/swagger';
import { DeviceStatus } from '@prisma/client';

export class DeviceResponseDto {
  @ApiProperty({
    format: 'uuid',
  })
  id!: string;

  @ApiProperty()
  hostname!: string;

  @ApiProperty()
  operatingSystem!: string;

  @ApiPropertyOptional({
    nullable: true,
  })
  architecture!: string | null;

  @ApiProperty()
  agentVersion!: string;

  @ApiProperty({
    enum: DeviceStatus,
  })
  status!: DeviceStatus;

  @ApiPropertyOptional({
    type: String,
    format: 'date-time',
    nullable: true,
  })
  lastSeenAt!: Date | null;

  @ApiProperty({
    type: String,
    format: 'date-time',
  })
  createdAt!: Date;
}

import { ApiProperty } from '@nestjs/swagger';
import { DeviceStatus } from '@prisma/client';

export class WazuhEnrollmentPayloadDto {
  @ApiProperty({
    example: '003',
  })
  agentId!: string;

  @ApiProperty({
    example: 'cyrp-e85f6bd5e17c',
  })
  agentName!: string;

  @ApiProperty({
    description:
      'Client key chỉ được trả về trong phản hồi enrollment này',
  })
  clientKey!: string;

  @ApiProperty({
    example: 'wazuh-manager.cyrp.local',
  })
  managerAddress!: string;

  @ApiProperty({
    example: 1514,
  })
  managerPort!: number;

  @ApiProperty({
    enum: ['tcp', 'udp'],
    example: 'tcp',
  })
  protocol!: 'tcp' | 'udp';
}

export class EnrollAgentResponseDto {
  @ApiProperty({
    format: 'uuid',
  })
  deviceId!: string;

  @ApiProperty({
    description:
      'Agent token chỉ được trả về đúng một lần',
  })
  agentToken!: string;

  @ApiProperty({
    enum: DeviceStatus,
  })
  status!: DeviceStatus;

  @ApiProperty({
    type: WazuhEnrollmentPayloadDto,
  })
  wazuh!: WazuhEnrollmentPayloadDto;
}

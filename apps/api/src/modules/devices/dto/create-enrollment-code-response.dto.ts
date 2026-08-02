import { ApiProperty } from '@nestjs/swagger';

export class CreateEnrollmentCodeResponseDto {
  @ApiProperty({
    example: 'CYRP-A7K9-M2Q4',
  })
  code!: string;

  @ApiProperty({
    example: 'CYRP-ENDPOINT-A7K9-M2Q4',
  })
  expectedAgentName!: string;

  @ApiProperty({
    example:
      'powershell -NoProfile -ExecutionPolicy Bypass -File .\\apps\\bootstrapper-windows\\Invoke-CyrpWazuhBootstrapper.ps1 ...',
  })
  bootstrapCommand!: string;

  @ApiProperty({
    type: String,
    format: 'date-time',
  })
  expiresAt!: Date;
}

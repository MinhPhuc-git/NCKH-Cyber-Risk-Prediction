import { ApiProperty } from '@nestjs/swagger';
import {
  IsUUID,
  Matches,
} from 'class-validator';

export class CreateWazuhBindingDto {
  @ApiProperty({
    format: 'uuid',
  })
  @IsUUID()
  deviceId!: string;

  @ApiProperty({
    example: '001',
  })
  @Matches(/^\d{3,}$/, {
    message:
      'wazuhAgentId phải gồm ít nhất 3 chữ số',
  })
  wazuhAgentId!: string;
}

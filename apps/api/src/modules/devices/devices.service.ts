import { Injectable } from '@nestjs/common';
import {
  createHash,
  randomInt,
} from 'node:crypto';

import type { CreateEnrollmentCodeResponseDto } from './dto/create-enrollment-code-response.dto';
import type { DeviceResponseDto } from './dto/device-response.dto';
import { DevicesRepository } from './devices.repository';

const ENROLLMENT_CODE_TTL_MS =
  30 * 60 * 1000;

const ENROLLMENT_ALPHABET =
  'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

@Injectable()
export class DevicesService {
  constructor(
    private readonly devicesRepository:
      DevicesRepository,
  ) {}

  async createEnrollmentCode(
    userId: string,
  ): Promise<CreateEnrollmentCodeResponseDto> {
    const code = this.generateEnrollmentCode();

    const codeHash = createHash('sha256')
      .update(code)
      .digest('hex');

    const expiresAt = new Date(
      Date.now() + ENROLLMENT_CODE_TTL_MS,
    );

    await this.devicesRepository.createEnrollmentCode(
      userId,
      codeHash,
      expiresAt,
    );

    const expectedAgentName =
      this.expectedAgentName(code);

    return {
      code,
      expectedAgentName,
      bootstrapCommand:
        this.buildBootstrapCommand(code),
      expiresAt,
    };
  }

  async listMyDevices(
    userId: string,
  ): Promise<DeviceResponseDto[]> {
    return this.devicesRepository.findManyByUserId(
      userId,
    );
  }

  private generateEnrollmentCode(): string {
    const characters = Array.from(
      {
        length: 8,
      },
      () =>
        ENROLLMENT_ALPHABET[
          randomInt(
            0,
            ENROLLMENT_ALPHABET.length,
          )
        ],
    ).join('');

    return [
      'CYRP',
      characters.slice(0, 4),
      characters.slice(4),
    ].join('-');
  }

  private expectedAgentName(
    code: string,
  ): string {
    return code.replace(
      'CYRP-',
      'CYRP-ENDPOINT-',
    );
  }

  private buildBootstrapCommand(
    code: string,
  ): string {
    const backendBaseUrl =
      process.env.CYRP_PUBLIC_BACKEND_BASE_URL?.trim() ||
      process.env.CYRP_API_BASE_URL?.trim() ||
      'http://<CYRP-HOST>:3001/api/v1';

    const bootstrapperPath =
      process.env.CYRP_BOOTSTRAPPER_PATH?.trim() ||
      '.\\apps\\bootstrapper-windows\\Invoke-CyrpWazuhBootstrapper.ps1';

    const msiPath =
      process.env.CYRP_WAZUH_AGENT_MSI_PATH?.trim() ||
      'C:\\Path\\wazuh-agent.msi';

    return [
      'powershell',
      '-NoProfile',
      '-ExecutionPolicy Bypass',
      `-File "${bootstrapperPath}"`,
      `-BackendBaseUrl "${backendBaseUrl}"`,
      `-EnrollmentCode "${code}"`,
      `-MsiPath "${msiPath}"`,
    ].join(' ');
  }
}

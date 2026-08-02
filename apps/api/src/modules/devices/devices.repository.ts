import { Injectable } from '@nestjs/common';

import { DatabaseService } from '../../database/database.service';
import {
  deviceResponseSelect,
  type DeviceResponseRecord,
} from './devices.types';

@Injectable()
export class DevicesRepository {
  constructor(
    private readonly database: DatabaseService,
  ) {}

  async createEnrollmentCode(
    userId: string,
    codeHash: string,
    expiresAt: Date,
  ): Promise<void> {
    await this.database.deviceEnrollmentCode.create({
      data: {
        userId,
        codeHash,
        expiresAt,
      },
    });
  }

  findManyByUserId(
    userId: string,
  ): Promise<DeviceResponseRecord[]> {
    return this.database.device.findMany({
      where: {
        userId,
      },
      select: deviceResponseSelect,
      orderBy: {
        createdAt: 'desc',
      },
    });
  }
}

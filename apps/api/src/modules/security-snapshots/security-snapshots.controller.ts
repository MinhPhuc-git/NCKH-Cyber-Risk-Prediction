import {
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { RoleCode } from '@prisma/client';

import type { AuthenticatedUser } from '../auth/auth.types';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { SecuritySnapshotsService } from './security-snapshots.service';

@ApiTags('security-snapshots')
@ApiBearerAuth('access-token')
@Roles(RoleCode.USER)
@Controller()
export class SecuritySnapshotsController {
  constructor(
    private readonly service:
      SecuritySnapshotsService,
  ) {}

  @Get('dashboard/security-overview')
  @ApiOperation({
    summary:
      'Lấy tổng quan an ninh của các thiết bị thuộc tài khoản',
  })
  overview(
    @CurrentUser()
    user: AuthenticatedUser,
  ) {
    return this.service.getOverview(
      user.id,
    );
  }

  @Get(
    'devices/:deviceId/security-snapshot',
  )
  @ApiOperation({
    summary:
      'Lấy snapshot bảo mật mới nhất của thiết bị',
  })
  snapshot(
    @CurrentUser()
    user: AuthenticatedUser,
    @Param(
      'deviceId',
      new ParseUUIDPipe(),
    )
    deviceId: string,
  ) {
    return this.service.getSnapshot(
      user.id,
      deviceId,
    );
  }

  @Post(
    'devices/:deviceId/security-sync',
  )
  @ApiOperation({
    summary:
      'Đồng bộ ngay dữ liệu Wazuh của thiết bị',
  })
  sync(
    @CurrentUser()
    user: AuthenticatedUser,
    @Param(
      'deviceId',
      new ParseUUIDPipe(),
    )
    deviceId: string,
  ) {
    return this.service.syncDevice(
      user.id,
      deviceId,
    );
  }
}

import {
  Body,
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
import { AnalysisRunsService } from './analysis-runs.service';
import { CreateAnalysisRunDto } from './dto/create-analysis-run.dto';

@ApiTags('analysis-runs')
@ApiBearerAuth('access-token')
@Roles(RoleCode.USER)
@Controller(
  'devices/:deviceId/analysis-runs',
)
export class AnalysisRunsController {
  constructor(
    private readonly service:
      AnalysisRunsService,
  ) {}

  @Post()
  @ApiOperation({
    summary:
      'Phân tích cảnh báo Wazuh gần nhất của thiết bị',
  })
  create(
    @CurrentUser()
    user: AuthenticatedUser,
    @Param(
      'deviceId',
      new ParseUUIDPipe(),
    )
    deviceId: string,
    @Body()
    dto: CreateAnalysisRunDto,
  ) {
    return this.service.create(
      user.id,
      deviceId,
      dto,
    );
  }

  @Get('latest')
  @ApiOperation({
    summary:
      'Lấy lần phân tích gần nhất của thiết bị',
  })
  latest(
    @CurrentUser()
    user: AuthenticatedUser,
    @Param(
      'deviceId',
      new ParseUUIDPipe(),
    )
    deviceId: string,
  ) {
    return this.service.latest(
      user.id,
      deviceId,
    );
  }
}

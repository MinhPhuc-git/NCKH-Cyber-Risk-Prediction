import {
  Controller,
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
import { AiPipelineCheckService } from './ai-pipeline-check.service';

@ApiTags('security-data')
@ApiBearerAuth('access-token')
@Roles(RoleCode.USER)
@Controller('devices')
export class AiPipelineCheckController {
  constructor(
    private readonly aiPipelineCheck: AiPipelineCheckService,
  ) {}

  @Post(':deviceId/ai-pipeline-check')
  @ApiOperation({
    summary:
      'Chạy AI pipeline cho thiết bị: export CVE từ Wazuh, inference XGBoost, import DB',
  })
  runAiPipelineCheck(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.aiPipelineCheck.runForUserDevice(user.id, deviceId);
  }
}

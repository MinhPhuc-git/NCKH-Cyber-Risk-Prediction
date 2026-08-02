import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
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
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Khởi tạo kiểm tra máy ở chế độ nền và trả runId ngay',
  })
  startAiPipelineCheck(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.aiPipelineCheck.startForUserDevice(user.id, deviceId);
  }

  @Get(':deviceId/ai-pipeline-check/:runId')
  @ApiOperation({
    summary: 'Lấy trạng thái một lần kiểm tra máy chạy nền',
  })
  getAiPipelineCheckStatus(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
    @Param('runId', new ParseUUIDPipe()) runId: string,
  ) {
    return this.aiPipelineCheck.getRunForUserDevice(
      user.id,
      deviceId,
      runId,
    );
  }
}

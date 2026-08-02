import {
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
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
import { ListDevicePackagesQueryDto } from './dto/list-device-packages-query.dto';
import { ListSyncRunsQueryDto } from './dto/list-sync-runs-query.dto';
import { ListVulnerabilitiesQueryDto } from './dto/list-vulnerabilities-query.dto';
import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';
import { SecurityDataSyncService } from './security-data-sync.service';
import { SecurityDataService } from './security-data.service';

@ApiTags('security-data')
@ApiBearerAuth('access-token')
@Roles(RoleCode.USER)
@Controller()
export class SecurityDataController {
  constructor(
    private readonly service: SecurityDataService,
    private readonly syncService: SecurityDataSyncService,
    private readonly aiPipelineImport: AiPipelineDataUserImportService,
  ) {}

  @Get('dashboard/data-overview')
  @ApiOperation({
    summary: 'Lấy tổng quan vulnerability và endpoint context của người dùng',
  })
  dashboard(@CurrentUser() user: AuthenticatedUser) {
    return this.service.getUserDashboard(user.id);
  }

  @Get('devices/:deviceId/overview')
  @ApiOperation({ summary: 'Lấy chi tiết tổng quan thiết bị' })
  deviceOverview(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.service.getDeviceOverview(user.id, deviceId);
  }

  @Post('devices/:deviceId/data-sync')
  @ApiOperation({
    summary: 'Đồng bộ vulnerability và endpoint context từ Wazuh',
  })
  syncDevice(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.syncService.syncForUser(user.id, deviceId);
  }

  @Get('devices/:deviceId/context')
  @ApiOperation({ summary: 'Lấy endpoint context snapshot mới nhất' })
  context(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.service.getLatestContext(user.id, deviceId);
  }

  @Get('devices/:deviceId/packages')
  @ApiOperation({ summary: 'Liệt kê package inventory đã chuẩn hóa của thiết bị' })
  packages(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
    @Query() query: ListDevicePackagesQueryDto,
  ) {
    return this.service.listUserDevicePackages(user.id, deviceId, query);
  }

  @Get('vulnerabilities')
  @ApiOperation({ summary: 'Liệt kê lỗ hổng của các thiết bị thuộc người dùng' })
  vulnerabilities(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListVulnerabilitiesQueryDto,
  ) {
    return this.service.listUserVulnerabilities(user.id, query);
  }

  @Get('vulnerabilities/:id')
  @ApiOperation({ summary: 'Lấy chi tiết lỗ hổng của thiết bị' })
  vulnerability(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.service.getUserVulnerability(user.id, id);
  }

  @Get('sync-runs')
  @ApiOperation({ summary: 'Liệt kê lịch sử đồng bộ của người dùng' })
  syncRuns(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListSyncRunsQueryDto,
  ) {
    return this.service.listUserSyncRuns(user.id, query);
  }
  @Post('devices/:deviceId/ai-predictions/import-data-user')
  @ApiOperation({
    summary: 'Import káº¿t quáº£ AI pipeline tá»« Data User JSON vÃ o database',
  })
  importAiPredictionsFromDataUser(
    @CurrentUser() user: AuthenticatedUser,
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.aiPipelineImport.importForUserDevice(user.id, deviceId);
  }

}

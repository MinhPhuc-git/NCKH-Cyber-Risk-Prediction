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

import { Roles } from '../auth/decorators/roles.decorator';
import { ListAdminDevicesQueryDto } from './dto/list-admin-devices-query.dto';
import { ListDevicePackagesQueryDto } from './dto/list-device-packages-query.dto';
import { ListSyncRunsQueryDto } from './dto/list-sync-runs-query.dto';
import { ListVulnerabilitiesQueryDto } from './dto/list-vulnerabilities-query.dto';
import { AiPipelineDataUserImportService } from './ai-pipeline-data-user-import.service';
import { SecurityDataSyncService } from './security-data-sync.service';
import { SecurityDataService } from './security-data.service';

@ApiTags('admin-security-data')
@ApiBearerAuth('access-token')
@Roles(RoleCode.ADMIN)
@Controller('admin')
export class AdminSecurityDataController {
  constructor(
    private readonly service: SecurityDataService,
    private readonly syncService: SecurityDataSyncService,
    private readonly aiPipelineImport: AiPipelineDataUserImportService,
  ) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Tổng quan vận hành cho quản trị viên' })
  dashboard() {
    return this.service.getAdminDashboard();
  }

  @Get('devices')
  @ApiOperation({ summary: 'Liệt kê toàn bộ thiết bị và chủ sở hữu' })
  devices(@Query() query: ListAdminDevicesQueryDto) {
    return this.service.listAdminDevices(query);
  }

  @Get('devices/:deviceId')
  @ApiOperation({ summary: 'Chi tiết thiết bị cho quản trị viên' })
  device(
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.service.getAdminDevice(deviceId);
  }

  @Get('devices/:deviceId/packages')
  @ApiOperation({ summary: 'Liệt kê package inventory của một thiết bị' })
  packages(
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
    @Query() query: ListDevicePackagesQueryDto,
  ) {
    return this.service.listAdminDevicePackages(deviceId, query);
  }

  @Post('devices/:deviceId/data-sync')
  @ApiOperation({ summary: 'Đồng bộ dữ liệu Wazuh của một thiết bị' })
  syncDevice(
    @Param('deviceId', new ParseUUIDPipe()) deviceId: string,
  ) {
    return this.syncService.syncForAdmin(deviceId);
  }

  @Post('data-sync/all')
  @ApiOperation({ summary: 'Đồng bộ dữ liệu Wazuh của mọi thiết bị đã binding' })
  syncAll() {
    return this.syncService.syncAllForAdmin();
  }

  @Get('wazuh-bindings')
  @ApiOperation({ summary: 'Liệt kê Wazuh Agent binding' })
  bindings() {
    return this.service.listAdminBindings();
  }

  @Get('vulnerabilities')
  @ApiOperation({ summary: 'Liệt kê lỗ hổng trên toàn hệ thống' })
  vulnerabilities(@Query() query: ListVulnerabilitiesQueryDto) {
    return this.service.listAdminVulnerabilities(query);
  }

  @Get('vulnerabilities/:id')
  @ApiOperation({ summary: 'Lấy chi tiết lỗ hổng trên toàn hệ thống' })
  vulnerability(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.service.getAdminVulnerability(id);
  }

  @Get('sync-runs')
  @ApiOperation({ summary: 'Liệt kê các lần đồng bộ dữ liệu' })
  syncRuns(@Query() query: ListSyncRunsQueryDto) {
    return this.service.listAdminSyncRuns(query);
  }

  @Get('cti-sources')
  @ApiOperation({ summary: 'Trạng thái nguồn CTI và thống kê dữ liệu' })
  ctiSources() {
    return this.service.listCtiSources();
  }

  @Get('system-health')
  @ApiOperation({ summary: 'Kiểm tra sức khỏe DB, Wazuh API và Indexer' })
  health() {
    return this.service.getSystemHealth();
  }
  @Post('ai-predictions/import-data-user')
  @ApiOperation({
    summary: 'Import káº¿t quáº£ AI pipeline tá»« Data User JSON vÃ o database',
  })
  importAiPredictionsFromDataUser() {
    return this.aiPipelineImport.importAllForAdmin();
  }
}

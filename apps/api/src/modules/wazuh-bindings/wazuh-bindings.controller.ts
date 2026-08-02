import {
  Body,
  Controller,
  Delete,
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

import { Roles } from '../auth/decorators/roles.decorator';
import { AgentRuntimeService } from './agent-runtime.service';
import { CreateWazuhBindingDto } from './dto/create-wazuh-binding.dto';
import { WazuhBindingsService } from './wazuh-bindings.service';

@ApiTags('wazuh-bindings')
@ApiBearerAuth('access-token')
@Roles(RoleCode.ADMIN)
@Controller('wazuh-bindings')
export class WazuhBindingsController {
  constructor(
    private readonly service:
      WazuhBindingsService,
    private readonly runtime:
      AgentRuntimeService,
  ) {}

  @Post()
  @ApiOperation({
    summary:
      'Liên kết Wazuh Agent hiện có với CYRP Device',
  })
  create(
    @Body()
    dto: CreateWazuhBindingDto,
  ) {
    return this.service
      .createOrUpdate(dto);
  }

  @Post('status-refresh')
  @ApiOperation({
    summary: 'Làm mới trạng thái của mọi Wazuh Agent đã binding',
  })
  refreshAllStatuses() {
    return this.runtime.refreshAll();
  }

  @Post(':deviceId/status-refresh')
  @ApiOperation({
    summary: 'Làm mới trạng thái Wazuh Agent của một CYRP Device',
  })
  refreshStatus(
    @Param('deviceId', new ParseUUIDPipe())
    deviceId: string,
  ) {
    return this.runtime.refreshDevice(deviceId);
  }

  @Delete(':deviceId')
  @ApiOperation({
    summary:
      'Gỡ liên kết giữa CYRP Device và Wazuh Agent, không xóa Agent trên Wazuh',
  })
  remove(
    @Param('deviceId', new ParseUUIDPipe())
    deviceId: string,
  ) {
    return this.service.remove(deviceId);
  }
}

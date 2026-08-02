import {
  Controller,
  Get,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { RoleCode } from '@prisma/client';

import { Roles } from '../auth/decorators/roles.decorator';
import { ListWazuhAgentsQueryDto } from './dto/list-wazuh-agents-query.dto';
import { WazuhService } from './wazuh.service';

@ApiTags('wazuh')
@ApiBearerAuth('access-token')
@Roles(RoleCode.ADMIN)
@Controller('wazuh')
export class WazuhController {
  constructor(
    private readonly wazuhService:
      WazuhService,
  ) {}

  @Get('status')
  @ApiOperation({
    summary:
      'Kiểm tra Wazuh Server API',
  })
  @ApiOkResponse()
  status() {
    return this.wazuhService
      .getStatus();
  }

  @Get('agents')
  @ApiOperation({
    summary:
      'Lấy danh sách Wazuh Agent',
  })
  @ApiOkResponse()
  agents(
    @Query()
    query:
      ListWazuhAgentsQueryDto,
  ) {
    return this.wazuhService
      .listAgents(query.limit);
  }
}

import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiOperation,
  ApiServiceUnavailableResponse,
  ApiTags,
} from '@nestjs/swagger';

import { Public } from '../auth/decorators/public.decorator';
import { AgentsService } from './agents.service';
import { EnrollAgentDto } from './dto/enroll-agent.dto';
import { EnrollAgentResponseDto } from './dto/enroll-agent-response.dto';

@ApiTags('agents')
@Controller('agents')
export class AgentsController {
  constructor(
    private readonly agentsService:
      AgentsService,
  ) {}

  @Public()
  @Post('enroll')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary:
      'Tạo CYRP Device, Wazuh Agent và binding bằng mã dùng một lần',
  })
  @ApiCreatedResponse({
    type: EnrollAgentResponseDto,
  })
  @ApiBadRequestResponse({
    description:
      'Mã liên kết không hợp lệ hoặc đã hết hạn',
  })
  @ApiConflictResponse({
    description:
      'Agent đã được liên kết',
  })
  @ApiServiceUnavailableResponse({
    description:
      'Không thể tạo Wazuh Agent',
  })
  enroll(
    @Body() dto: EnrollAgentDto,
  ): Promise<EnrollAgentResponseDto> {
    return this.agentsService.enroll(dto);
  }
}

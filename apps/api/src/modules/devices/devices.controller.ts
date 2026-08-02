import {
  Controller,
  Get,
  Post,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { RoleCode } from '@prisma/client';

import type { AuthenticatedUser } from '../auth/auth.types';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { CreateEnrollmentCodeResponseDto } from './dto/create-enrollment-code-response.dto';
import { DeviceResponseDto } from './dto/device-response.dto';
import { DevicesService } from './devices.service';

@ApiTags('devices')
@ApiBearerAuth('access-token')
@Roles(RoleCode.USER)
@Controller('devices')
export class DevicesController {
  constructor(
    private readonly devicesService:
      DevicesService,
  ) {}

  @Get()
  @ApiOperation({
    summary:
      'Lấy danh sách thiết bị của người dùng hiện tại',
  })
  @ApiOkResponse({
    type: DeviceResponseDto,
    isArray: true,
  })
  listMyDevices(
    @CurrentUser()
    user: AuthenticatedUser,
  ): Promise<DeviceResponseDto[]> {
    return this.devicesService.listMyDevices(
      user.id,
    );
  }

  @Post('enrollment-codes')
  @ApiOperation({
    summary:
      'Tạo mã liên kết thiết bị dùng một lần',
  })
  @ApiCreatedResponse({
    type: CreateEnrollmentCodeResponseDto,
  })
  createEnrollmentCode(
    @CurrentUser()
    user: AuthenticatedUser,
  ): Promise<CreateEnrollmentCodeResponseDto> {
    return this.devicesService.createEnrollmentCode(
      user.id,
    );
  }
}

import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';

import {
  Public,
} from '../auth/decorators/public.decorator';
import { RegisterUserDto } from './dto/register-user.dto';
import { RegisterUserResponseDto } from './dto/register-user-response.dto';
import { RegistrationService } from './registration.service';

@ApiTags('auth')
@Controller('auth')
export class RegistrationController {
  constructor(
    private readonly registrationService:
      RegistrationService,
  ) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary:
      'Đăng ký tài khoản USER',
  })
  @ApiCreatedResponse({
    type: RegisterUserResponseDto,
  })
  @ApiConflictResponse({
    description: 'Email đã tồn tại',
  })
  register(
    @Body() dto: RegisterUserDto,
  ): Promise<RegisterUserResponseDto> {
    return this.registrationService.register(
      dto,
    );
  }
}

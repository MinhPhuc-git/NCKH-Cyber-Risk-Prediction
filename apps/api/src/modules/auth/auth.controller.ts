import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

import { AuthService } from './auth.service';
import type { AuthenticatedUser } from './auth.types';
import { CurrentUser } from './decorators/current-user.decorator';
import {
  Public,
} from './decorators/public.decorator';
import { LoginDto } from './dto/login.dto';
import {
  AuthenticatedUserDto,
  LoginResponseDto,
} from './dto/login-response.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Đăng nhập vào CYRP Platform',
  })
  @ApiOkResponse({
    type: LoginResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Email hoặc mật khẩu không đúng',
  })
  @ApiForbiddenResponse({
    description: 'Tài khoản đã bị vô hiệu hóa',
  })
  login(
    @Body() loginDto: LoginDto,
  ): Promise<LoginResponseDto> {
    return this.authService.login(loginDto);
  }

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.FORBIDDEN)
  @ApiOperation({
    summary:
      'Đăng ký công khai đã bị tắt trong mô hình doanh nghiệp',
  })
  @ApiForbiddenResponse({
    description:
      'Tài khoản USER phải được Admin cấp phát',
  })
  registerDisabled(): never {
    throw new ForbiddenException({
      code: 'PUBLIC_REGISTRATION_DISABLED',
      message:
        'Đăng ký công khai đã bị tắt. Tài khoản USER phải được Admin cấp phát.',
    });
  }

  @Get('me')
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Lấy thông tin người dùng đang đăng nhập',
  })
  @ApiOkResponse({
    type: AuthenticatedUserDto,
  })
  @ApiUnauthorizedResponse({
    description:
      'Thiếu token, token không hợp lệ hoặc đã hết hạn',
  })
  @ApiForbiddenResponse({
    description: 'Tài khoản đã bị vô hiệu hóa',
  })
  getCurrentUser(
    @CurrentUser() user: AuthenticatedUser,
  ): AuthenticatedUserDto {
    return user;
  }
}

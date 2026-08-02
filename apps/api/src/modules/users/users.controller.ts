import {
  Body,
  Controller,
  Get,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RoleCode } from '@prisma/client';

import {
  Roles,
} from '../auth/decorators/roles.decorator';
import {
  CreateUserDto,
} from './dto/create-user.dto';
import {
  CreateUserResponseDto,
} from './dto/create-user-response.dto';
import { ListUsersQueryDto } from './dto/list-users-query.dto';
import {
  ListUsersResponseDto,
} from './dto/list-users-response.dto';
import { UsersService } from './users.service';

@ApiTags('users')
@ApiBearerAuth('access-token')
@Roles(RoleCode.ADMIN)
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService:
      UsersService,
  ) {}

  @Get()
  @ApiOperation({
    summary:
      'Lấy danh sách người dùng',
  })
  @ApiOkResponse({
    type: ListUsersResponseDto,
  })
  @ApiUnauthorizedResponse({
    description:
      'Thiếu token hoặc token không hợp lệ',
  })
  @ApiForbiddenResponse({
    description:
      'Tài khoản không có quyền ADMIN',
  })
  list(
    @Query() query: ListUsersQueryDto,
  ): Promise<ListUsersResponseDto> {
    return this.usersService.list(query);
  }

  @Post()
  @ApiOperation({
    summary:
      'Admin tạo tài khoản USER mới',
  })
  @ApiCreatedResponse({
    type: CreateUserResponseDto,
  })
  @ApiUnauthorizedResponse({
    description:
      'Thiếu token hoặc token không hợp lệ',
  })
  @ApiForbiddenResponse({
    description:
      'Tài khoản không có quyền ADMIN',
  })
  createUser(
    @Body() createUserDto: CreateUserDto,
  ): Promise<CreateUserResponseDto> {
    return this.usersService.createByAdmin(
      createUserDto,
    );
  }
}

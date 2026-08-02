import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty({
    example: 'Nguyen Van A',
    maxLength: 160,
  })
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string'
      ? value.trim()
      : value,
  )
  @IsString()
  @MinLength(1)
  @MaxLength(160)
  fullName!: string;

  @ApiProperty({
    example: 'user@cyrp.local',
    format: 'email',
  })
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string'
      ? value.trim().toLowerCase()
      : value,
  )
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @ApiProperty({
    minLength: 12,
    maxLength: 128,
  })
  @IsString()
  @MinLength(12)
  @MaxLength(128)
  password!: string;
}

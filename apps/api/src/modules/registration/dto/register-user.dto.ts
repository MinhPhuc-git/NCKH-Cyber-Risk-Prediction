import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class RegisterUserDto {
  @ApiProperty({
    example: 'Nguyen Van A',
    minLength: 2,
    maxLength: 100,
  })
  @Transform(({ value }: { value: unknown }) => {
    if (typeof value !== 'string') {
      return value;
    }

    return value.trim();
  })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  fullName!: string;

  @ApiProperty({
    example: 'user@example.com',
    format: 'email',
  })
  @Transform(({ value }: { value: unknown }) => {
    if (typeof value !== 'string') {
      return value;
    }

    return value.trim().toLowerCase();
  })
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

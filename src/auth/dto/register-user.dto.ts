import { IsEmail, IsEnum, IsString } from 'class-validator';
import { Roles } from '../enums/roles-user.enum';

export class RegisterUserDto {
  @IsString()
  fullName: string;
  @IsEmail()
  email: string;
  @IsString()
  password: string;
}

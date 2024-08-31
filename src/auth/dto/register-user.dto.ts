import { IsEmail, IsEnum, IsNumber, IsObject, IsString } from 'class-validator';
import { Dirrecion } from '../interfaces';
import { Roles } from '../enums/roles-user.enum';

export class RegisterUserDto {
  @IsString()
  fullName: string;
  @IsEmail()
  email: string;
  @IsString()
  password: string;
  @IsObject()
  direccion: Dirrecion;
  @IsNumber()
  telefono: number;
  @IsEnum(() => [Roles])
  roles: Roles[] = [Roles.CLIENT];
}

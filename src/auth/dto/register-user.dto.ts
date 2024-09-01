import {
  IsEmail,
  IsEnum,
  IsInt,
  IsNumber,
  IsObject,
  IsString,
} from 'class-validator';
import { Roles } from '../enums/roles-user.enum';

export class Direccion {
  @IsString()
  city: string;
  @IsString()
  street: string;
  @IsInt()
  postal: number;
}
export class RegisterUserDto {
  @IsString()
  fullName: string;
  @IsEmail()
  email: string;
  @IsString()
  password: string;
  @IsObject()
  direccion: Direccion;
  @IsNumber()
  telefono: number;
  @IsEnum(Roles, { each: true })
  roles: Roles[] = [Roles.CLIENT];
}

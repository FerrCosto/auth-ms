import {
  IsEmail,
  IsEnum,
  IsInt,
  IsObject,
  IsPhoneNumber,
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
  @IsPhoneNumber('CO')
  telefono: string;
  @IsEnum(Roles, { each: true })
  roles: Roles[] = [Roles.CLIENT];
}

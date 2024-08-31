import { Roles } from '@prisma/client';
import { Dirrecion } from './';

export interface JwtPayload {
  id: string;
  fullName: string;
  email: string;
  telefono: number;
  roles: Roles[];
  direccion: Dirrecion;
}

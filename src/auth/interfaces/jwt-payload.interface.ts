import { Roles } from '../enums/roles-user.enum';
import { Dirrecion } from './';

export interface JwtPayload {
  id: string;
  fullName: string;
  email: string;
  telefono?: number | null;
  role: Roles;
  direccion?: Dirrecion | null;
}

import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { LoginUserDto } from './dto/login-user.dto';
import { envs } from 'src/config/envs.config';
import { Roles } from './enums/roles-user.enum';
import { NATS_SERVICE } from 'src/config';
import { catchError, firstValueFrom } from 'rxjs';
@Injectable()
export class AuthService {
  constructor(
    @Inject(NATS_SERVICE) private readonly client: ClientProxy,
    private readonly jwtSecret: JwtService,
  ) {}

  async singJwt(user: JwtPayload) {
    return this.jwtSecret.signAsync(user);
  }
  async singUp(registerUserDto: RegisterUserDto) {
    try {
      const data = {
        fullName: registerUserDto.fullName,
        email: registerUserDto.email,
        password: registerUserDto.password,
      };

      const userInfo: any = await firstValueFrom(
        this.client.send('user.create', data).pipe(
          catchError((error) => {
            throw new RpcException(error);
          }),
        ),
      );

      if (!userInfo) {
        throw new RpcException({
          status: 400,
          message: 'Error al llamar al microservicio',
        });
      }

      const { id, ...resData } = userInfo;
      const tokenPayload = {
        id,
        fullName: userInfo.fullName,
        email: userInfo.email,
        ...(userInfo.telefono && { telefono: userInfo.telefono }),
        role: userInfo.role,
      };
      return {
        token: await this.singJwt(tokenPayload),
      };
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 500,
        message: 'Mirar los logs del servidor',
      });
    }
  }

  async singIn(loginUserDto: LoginUserDto) {
    const user = await firstValueFrom(
      this.client.send('user.verify', loginUserDto).pipe(
        catchError((error) => {
          throw new RpcException(error);
        }),
      ),
    );

    const { id, ...resData } = user;
    console.log(resData);
    const tokenPayload: JwtPayload = {
      id,
      fullName: resData.fullName,
      email: resData.email,
      ...(resData.telefono && { telefono: resData.telefono }),
      role: resData.role,
      ...(resData.addresses && { direccion: resData.addresses[0] }),
    };
    return {
      token: await this.singJwt(tokenPayload),
    };
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtSecret.verify(token, {
        secret: envs.jwt_secret,
      });

      return {
        user,
        token: await this.singJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid Token',
      });
    }
  }
}

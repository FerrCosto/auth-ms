import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { LoginUserDto } from './dto/login-user.dto';
import { envs } from 'src/config/envs.config';
import { Roles } from './enums/roles-user.enum';
import { NATS_SERVICE } from 'src/config';
import { firstValueFrom } from 'rxjs';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(
    @Inject(NATS_SERVICE) private readonly client: ClientProxy,
    private readonly jwtSecret: JwtService,
  ) {
    super();
  }
  async onModuleInit() {
    await this.$connect();
    console.log('Contectado a la base: ', envs.database_url);
  }

  async singJwt(user: JwtPayload) {
    return this.jwtSecret.signAsync(user);
  }
  async singUp(registerUserDto: RegisterUserDto) {
    try {
      const user = await this.user.findUnique({
        where: {
          email: registerUserDto.email,
        },
      });

      if (user)
        throw new RpcException({
          status: 400,
          message: 'User already exits',
        });

      const data = {
        fullName: registerUserDto.fullName,
        roles: Roles.CLIENT,
        email: registerUserDto.email,
      };

      const userInfo: any = await firstValueFrom(
        this.client.send('user.create', data),
      );

      if (!userInfo) {
        console.log(user);
        throw new RpcException({
          status: 400,
          message: 'Error al llamar al microservicio',
        });
      }

      const createUser = await this.user.create({
        data: {
          ...data,
          password: bcrypt.hashSync(registerUserDto.password, 10),
        },
      });

      const { id, ...resData } = createUser;
      const tokenPayload = {
        id,
        fullName: userInfo.fullName,
        email: userInfo.email,
        telefono: userInfo.telefono,
        role: userInfo.roles,
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
    const { password, email } = loginUserDto;

    const user = await this.user.findUnique({
      where: { email },
    });
    if (!user)
      throw new RpcException({
        status: 400,
        message: `Email/Password not valid`,
      });
    const verifyPassword = bcrypt.compareSync(password, user.password);
    if (!verifyPassword)
      throw new RpcException({
        status: 400,
        message: `Email/Password not valid`,
      });

    const userInfo: any = await firstValueFrom(
      this.client.send('user.findEmail', email),
    );

    const { id, ...resData } = user;
    const tokenPayload: JwtPayload = {
      id,
      fullName: userInfo.fullName,
      email: userInfo.email,
      ...(userInfo.telefono && { telefono: userInfo.telefono }),
      role: userInfo.role,
      ...(userInfo.direccion && { direccion: userInfo.direccion }),
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

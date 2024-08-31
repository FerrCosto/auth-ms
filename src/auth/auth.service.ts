import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { RpcException } from '@nestjs/microservices';
import { LoginUserDto } from './dto/login-user.dto';
import { envs } from 'src/config/envs.config';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(private readonly jwtSecret: JwtService) {
    super();
  }
  async onModuleInit() {
    await this.$connect();
  }

  async singJwt(user: JwtPayload) {
    return this.jwtSecret.signAsync(user);
  }
  async singUp(registerUserDto: RegisterUserDto) {
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

    const createUser = await this.user.create({
      data: {
        direccion: registerUserDto.direccion,
        fullName: registerUserDto.fullName,
        telefono: registerUserDto.telefono,
        roles: registerUserDto.roles,
        email: registerUserDto.email,
        password: bcrypt.hashSync(registerUserDto.password, 10),
      },
    });
    const { password: _, ...resData } = createUser;
    return {
      user: resData,
      token: await this.singJwt(resData),
    };
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
    const { password: _, ...resData } = user;
    return {
      user: resData,
      token: await this.singJwt(resData),
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

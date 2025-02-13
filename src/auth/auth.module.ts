import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config/envs.config';
import { NatsModule } from '../transports/nats.module';

@Module({
  imports: [
    NatsModule,
    JwtModule.register({
      global: true,
      secret: envs.jwt_secret,
      signOptions: {
        expiresIn: '2h',
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}

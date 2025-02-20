import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginUserDto, RegisterUserDto } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  async singUp(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.singUp(registerUserDto);
  }
  @MessagePattern('auth.login.user')
  async singIn(@Payload() loginUserDto: LoginUserDto) {
    return this.authService.singIn(loginUserDto);
  }

  @MessagePattern('auth.verify.token')
  async verifyToken(@Payload() token: string) {
    return this.authService.verifyToken(token);
  }
}

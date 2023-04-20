import { Controller, Post, Get, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() payload: AuthDto) {
    return this.authService.signup(payload);
  }

  @Post('signin')
  signin(@Body() payload: AuthDto) {
    return this.authService.signin(payload);
  }

  @Get('signout')
  signout() {
    return this.authService.signout();
  }
}
